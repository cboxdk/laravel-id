<?php

declare(strict_types=1);

use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * GRANTS AND TOKENS END WITH THE DECISION THAT ENDS THEM.
 *
 * A suspended or archived organization kept getting tokens (refresh, client_credentials)
 * and its earlier tokens stayed active; a withdrawn grant left its access tokens for token
 * exchange to renew; a deleted app's tokens outlived it; a closed organization's SCIM token
 * kept provisioning. Each is refused now, and reactivation restores what was refused.
 */
beforeEach(function (): void {
    User::query()->create(['id' => 'user_1', 'email' => 'user_1@tokens.test', 'status' => UserStatus::Active]);
    $this->org = app(Organizations::class)->create(new NewOrganization('Acme', 'acme-'.uniqid()));
});

it('mints nothing for a closed organization, by refresh or by client_credentials, and again after reactivation', function (): void {
    $client = $this->makeClient(['openid'], grantTypes: ['refresh_token', 'client_credentials'], organizationId: $this->org->id)->client;
    $refresh = app(RefreshTokens::class)->issue($client, 'user_1', $this->org->id, ['openid']);

    app(Organizations::class)->suspend($this->org->id, 'sub_operator');

    expect(fn () => app(RefreshTokens::class)->rotate($client->client_id, $refresh))->toThrow(InvalidGrant::class)
        ->and(fn () => app(TokenIssuer::class)->issueClientCredentials($client))->toThrow(InvalidGrant::class);

    app(Organizations::class)->reactivate($this->org->id, 'sub_operator');

    // Not consumed by the refusal.
    expect(app(RefreshTokens::class)->rotate($client->client_id, $refresh)->refreshToken)->toBeString();
})->group('security');

it('calls a closed organization\'s token inactive, and a deleted app\'s', function (): void {
    $client = $this->makeClient(['openid'], organizationId: $this->org->id)->client;
    $token = app(TokenIssuer::class)->issueClientCredentials($client)->token;

    expect(app(TokenIntrospector::class)->introspect($token)->active)->toBeTrue();

    app(Organizations::class)->suspend($this->org->id, 'sub_operator');
    expect(app(TokenIntrospector::class)->introspect($token)->active)->toBeFalse();

    app(Organizations::class)->reactivate($this->org->id, 'sub_operator');
    expect(app(TokenIntrospector::class)->introspect($token)->active)->toBeTrue();

    app(ClientRegistry::class)->delete($client);
    expect(app(TokenIntrospector::class)->introspect($token)->active)->toBeFalse()
        ->and(AccessToken::query()->where('client_id', $client->client_id)->whereNull('revoked_at')->exists())->toBeFalse();
})->group('security');

it('revokes a withdrawn grant\'s access tokens, but not on a role change', function (): void {
    $client = $this->makeClient(['openid'], grantTypes: ['refresh_token'])->client;
    app(RefreshTokens::class)->issue($client, 'user_1', null, ['openid']);
    $token = app(TokenIssuer::class)->issueForUser($client, 'user_1', null, ['openid'])->token;

    app(RefreshTokens::class)->revokeForUser('user_1');
    expect(app(TokenIntrospector::class)->introspect($token)->active)->toBeTrue();

    app(RefreshTokens::class)->revokeForUserAndClient('user_1', $client->client_id);
    expect(app(TokenIntrospector::class)->introspect($token)->active)->toBeFalse();
})->group('security');

it('lets an archived organization\'s SCIM directory in no more', function (): void {
    $directory = app(Directories::class)->register($this->org->id, 'Okta');

    app(Organizations::class)->archive($this->org->id, 'sub_operator');
    expect(app(Directories::class)->authenticate($directory->token))->toBeNull();
})->group('security');
