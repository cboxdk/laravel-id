<?php

declare(strict_types=1);

use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Crypto\SecretPrefix;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Models\RefreshToken;
use Cbox\Id\OAuthServer\Models\StoredClientSecret;
use Cbox\Id\OAuthServer\ValueObjects\ClientSecret;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * v3 mints every secret as `cbid_<kind>_…`, and nothing revokes the v2 forms. Each test
 * below writes a secret exactly as v2.x stored it (the SHA-256 of a `csec_`/`rt_`/`scim_`
 * plaintext) and proves it still does its job — then that what comes back is the new form.
 */
const GRACE_VERIFIER = 'a-sufficiently-long-code-verifier-for-the-grace-test';

beforeEach(function (): void {
    User::query()->create(['id' => 'user_grace', 'email' => 'grace@prefix.test', 'status' => UserStatus::Active]);
});

function v2Secret(string $legacyPrefix): string
{
    return $legacyPrefix.bin2hex(random_bytes(32));
}

it('mints every kind in the cbid_ form, never the legacy one', function (SecretPrefix $kind): void {
    $secret = $kind->mint();

    expect($secret)->toStartWith('cbid_')
        ->toStartWith($kind->value)
        ->toHaveLength(strlen($kind->value) + 64)
        ->and(str_starts_with($secret, $kind->legacy()))->toBeFalse();
})->with(SecretPrefix::cases());

it('exchanges a code with a v2 csec_ client secret, which nothing revoked', function (): void {
    $registered = $this->makeClient(['openid', 'offline_access'], grantTypes: ['authorization_code', 'refresh_token']);
    $client = $registered->client;

    // The client as v2.x left it: one live secret, in the old form.
    $legacy = v2Secret('csec_');
    StoredClientSecret::query()->where('oauth_client_id', $client->id)->delete();
    StoredClientSecret::query()->create([
        'oauth_client_id' => $client->id,
        'secret_hash' => ClientSecret::hash($legacy),
        'hint' => substr($legacy, -ClientSecret::HINT_LENGTH),
    ]);

    $code = app(AuthorizationCodes::class)->issue(
        $client->client_id, 'user_grace', null, 'https://app.test/cb', ['openid', 'offline_access'],
        Base64Url::encode(hash('sha256', GRACE_VERIFIER, true)), 'S256',
    );

    expect($code)->toStartWith('cbid_ac_');

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $client->client_id,
        'client_secret' => $legacy,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => GRACE_VERIFIER,
    ])->assertOk();

    expect($registered->secret)->toStartWith('cbid_cs_')
        ->and($response->json('refresh_token'))->toStartWith('cbid_rt_');
});

it('refreshes with a v2 rt_ refresh token and hands back a cbid_rt_ one', function (): void {
    $registered = $this->makeClient(['openid', 'offline_access'], grantTypes: ['authorization_code', 'refresh_token']);

    $legacy = v2Secret('rt_');
    RefreshToken::query()->create([
        'token_hash' => hash('sha256', $legacy),
        'family_id' => 'fam-grace',
        'client_id' => $registered->client->client_id,
        'user_id' => 'user_grace',
        'organization_id' => null,
        'scopes' => ['openid', 'offline_access'],
        'expires_at' => now()->addDays(30),
    ]);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'refresh_token' => $legacy,
    ])->assertOk();

    expect($response->json('access_token'))->toBeString()
        ->and($response->json('refresh_token'))->toStartWith('cbid_rt_');
});

it('syncs with a v2 scim_ bearer token the customer never rotated', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeDirectory($org->id);

    expect($registered->token)->toStartWith('cbid_scim_');

    // The token as the customer's IdP holds it since v2.x.
    $legacy = v2Secret('scim_');
    Directory::query()->whereKey($registered->directory->id)->update(['bearer_token_hash' => hash('sha256', $legacy)]);

    $this->postJson('/scim/v2/Users', [
        'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
        'userName' => 'dana',
        'externalId' => 'okta|grace',
        'emails' => [['value' => 'dana@grace.test', 'primary' => true]],
        'active' => true,
    ], ['Authorization' => 'Bearer '.$legacy])->assertStatus(201);

    $this->assertDatabaseHas('directory_users', ['external_id' => 'okta|grace']);
});
