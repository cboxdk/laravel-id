<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Models\RefreshToken;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('honours a configured access-token lifetime', function (): void {
    config()->set('cbox-id.oauth.access_token_ttl', 120);
    $this->app->forgetInstance(TokenIssuer::class);

    $token = app(TokenIssuer::class)->issueClientCredentials($this->makeClient(['api.read'])->client);

    expect($token->expiresIn)->toBe(120);
});

it('falls back to the 15-minute default when unconfigured', function (): void {
    $token = app(TokenIssuer::class)->issueClientCredentials($this->makeClient(['api.read'])->client);

    expect($token->expiresIn)->toBe(900);
});

it('revokes every active refresh token a user holds (the RBAC freshness lever)', function (): void {
    $org = $this->makeOrganization();
    $client = $this->makeClient(['api.read'])->client;
    $refresh = app(RefreshTokens::class);

    $refresh->issue($client, 'user_1', $org->id, ['api.read']);
    $refresh->issue($client, 'user_1', $org->id, ['api.read']);
    $refresh->issue($client, 'user_2', $org->id, ['api.read']); // a different user, untouched

    $revoked = $refresh->revokeForUser('user_1', $org->id);

    expect($revoked)->toBe(2)
        ->and(RefreshToken::query()->where('user_id', 'user_1')->whereNull('revoked_at')->count())->toBe(0)
        ->and(RefreshToken::query()->where('user_id', 'user_2')->whereNull('revoked_at')->count())->toBe(1);
});

it('scopes user revocation to one organization when asked', function (): void {
    $orgA = $this->makeOrganization('A');
    $orgB = $this->makeOrganization('B');
    $client = $this->makeClient(['api.read'])->client;
    $refresh = app(RefreshTokens::class);

    $refresh->issue($client, 'user_1', $orgA->id, ['api.read']);
    $refresh->issue($client, 'user_1', $orgB->id, ['api.read']);

    expect($refresh->revokeForUser('user_1', $orgA->id))->toBe(1)
        ->and(RefreshToken::query()->where('organization_id', $orgB->id)->whereNull('revoked_at')->count())->toBe(1);
});

/**
 * WHAT A PERSON SEES WHEN THEY ASK "WHAT CAN ACT AS ME".
 *
 * Rotation mints a refresh-token row on every use, so the rows describe freshness rather
 * than consent — a screen built on them would offer somebody eleven identical entries for
 * one approval and ask which to revoke. One row per CLIENT is the fact they can act on.
 */
it('collapses a rotated grant to one application', function (): void {
    $org = $this->makeOrganization();
    $client = $this->makeClient(['api.read'])->client;
    $refresh = app(RefreshTokens::class);

    $token = $refresh->issue($client, 'user_1', $org->id, ['api.read']);
    $rotated = $refresh->rotate($client->client_id, $token);
    $refresh->rotate($client->client_id, $rotated->refreshToken);

    $applications = $refresh->connectedApplications('user_1');

    expect($applications)->toHaveCount(1)
        ->and($applications[0]->clientId)->toBe($client->client_id)
        // The client's NAME, because a client id is not a thing to show somebody.
        ->and($applications[0]->name)->toBe($client->name);
});

it('shows the union of what an application may do, not only its newest grant', function (): void {
    $org = $this->makeOrganization();
    $client = $this->makeClient(['api.read', 'offline_access'])->client;
    $refresh = app(RefreshTokens::class);

    $refresh->issue($client, 'user_1', $org->id, ['api.read']);
    $refresh->issue($client, 'user_1', $org->id, ['offline_access']);

    $applications = $refresh->connectedApplications('user_1');

    expect($applications)->toHaveCount(1)
        ->and($applications[0]->scopes)->toContain('api.read')
        ->and($applications[0]->scopes)->toContain('offline_access')
        // Worth saying out loud on the screen: this one can act while nobody is there.
        ->and($applications[0]->actsOffline())->toBeTrue();
});

it('shows nothing for an application whose access was withdrawn', function (): void {
    $org = $this->makeOrganization();
    $client = $this->makeClient(['api.read'])->client;
    $refresh = app(RefreshTokens::class);

    $refresh->issue($client, 'user_1', $org->id, ['api.read']);
    $refresh->revokeForUserAndClient('user_1', $client->client_id);

    expect($refresh->connectedApplications('user_1'))->toBe([]);
});

/**
 * THE WHOLE POINT OF SHOWING SOMEBODY THEIR APPLICATIONS is that they can remove ONE.
 * `revokeForUser()` signs them out of everything, which is the right answer to "my account
 * is compromised" and the wrong answer to "I do not use that CLI any more".
 */
it('withdraws one application without touching the others', function (): void {
    $org = $this->makeOrganization();
    $keep = $this->makeClient(['api.read'])->client;
    $drop = $this->makeClient(['api.read'])->client;
    $refresh = app(RefreshTokens::class);

    $kept = $refresh->issue($keep, 'user_1', $org->id, ['api.read']);
    $refresh->issue($drop, 'user_1', $org->id, ['api.read']);

    expect($refresh->revokeForUserAndClient('user_1', $drop->client_id))->toBe(1);

    $applications = $refresh->connectedApplications('user_1');

    expect($applications)->toHaveCount(1)
        ->and($applications[0]->clientId)->toBe($keep->client_id)
        // And the one they kept still works, which is the half a blunt revoke gets wrong.
        ->and($refresh->rotate($keep->client_id, $kept))->not->toBeNull();
})->group('security');

it('never shows one person another person\'s applications', function (): void {
    $org = $this->makeOrganization();
    $client = $this->makeClient(['api.read'])->client;
    $refresh = app(RefreshTokens::class);

    $refresh->issue($client, 'user_1', $org->id, ['api.read']);

    expect($refresh->connectedApplications('user_2'))->toBe([]);
})->group('security');
