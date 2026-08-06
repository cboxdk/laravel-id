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
