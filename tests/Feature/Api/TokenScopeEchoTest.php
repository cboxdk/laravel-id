<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * RFC 6749 §5.1: `scope` is OPTIONAL only "if identical to the scope requested by the
 * client; otherwise, REQUIRED."
 *
 * The issuer silently filters a request down to the client's registered set, so a
 * client that asked for more used to get a 200 with a narrower token and NOTHING in
 * the response saying so — every conformant library (AppAuth, node-openid-client,
 * Spring Security) then assumes the full requested scope was granted, and the next API
 * call 403s with nothing to diagnose it against.
 */
it('echoes the granted scope when the request was down-scoped', function (): void {
    $registered = $this->makeClient(['api.read'], grantTypes: ['client_credentials']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'api.read api.write',
    ])
        ->assertOk()
        ->assertJsonPath('scope', 'api.read');
});

it('omits scope when the granted set is identical to the request', function (): void {
    $registered = $this->makeClient(['api.read', 'api.write'], grantTypes: ['client_credentials']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'api.read api.write',
    ])
        ->assertOk()
        ->assertJsonMissingPath('scope');
});

it('echoes the granted scope on an omitted request, which inherits the whole registered set', function (): void {
    $registered = $this->makeClient(['api.read', 'api.write'], grantTypes: ['client_credentials']);

    // An empty request is NOT identical to "api.read api.write", so §5.1 requires it.
    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])
        ->assertOk()
        ->assertJsonPath('scope', 'api.read api.write');
});

it('echoes the granted scope on a down-scoped authorization_code exchange', function (): void {
    $registered = $this->makeClient(['openid', 'profile'], ClientType::Public, ['authorization_code']);
    $verifier = 'a-sufficiently-long-code-verifier-1234567890';

    // The code carries what the client ASKED for — `organizations` and
    // `offline_access` are outside its registered set and are filtered at mint time.
    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user_42',
        'org_a',
        'https://app.test/cb',
        ['openid', 'profile', 'organizations', 'offline_access'],
        Base64Url::encode(hash('sha256', $verifier, true)),
    );

    $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
    ])
        ->assertOk()
        ->assertJsonPath('scope', 'openid profile');
});

it('echoes the granted scope when a refresh carries scopes the client has since lost', function (): void {
    $registered = $this->makeClient(['api.read', 'api.write'], grantTypes: ['client_credentials', 'refresh_token']);

    $refresh = app(RefreshTokens::class)->issue($registered->client, 'user_42', 'org_a', ['api.read', 'api.write']);

    // The client's registration is narrowed after the refresh token was minted.
    $registered->client->forceFill(['scopes' => ['api.read']])->save();

    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'refresh_token' => $refresh,
    ])
        ->assertOk()
        ->assertJsonPath('scope', 'api.read');
});

/**
 * Granting NOTHING is not a partial grant.
 *
 * Down-scoping with an honest echo is correct and deliberate — the two tests above pin
 * it. But when nothing survives the filter, §5.1's ABNF has no empty production for
 * `scope`, so the echo cannot be sent and the response becomes indistinguishable from
 * "you were granted everything you asked for". The client proceeds on authority it does
 * not hold and discovers it at the resource server, with nothing to diagnose against.
 *
 * §5.2 has the error for a request that exceeds what may be granted.
 */
it('refuses a request for scopes the client holds none of', function (): void {
    $registered = $this->makeClient(['api.read'], grantTypes: ['client_credentials']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'billing.write admin.everything',
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_scope');
});

/**
 * And a request that overlaps still succeeds, narrowed and echoed — the behaviour above
 * must not have been widened into a blanket refusal.
 */
it('still narrows a partially-registered request rather than refusing it', function (): void {
    $registered = $this->makeClient(['api.read'], grantTypes: ['client_credentials']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'api.read billing.write',
    ])
        ->assertOk()
        ->assertJsonPath('scope', 'api.read');
});
