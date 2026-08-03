<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Crypto\ValueObjects\TokenClaims;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/*
 * A refresh renews the ID Token, not only the access token.
 *
 * WHY THIS FILE EXISTS. The refresh grant returned an access token and a refresh
 * token and nothing else, which is invisible for as long as every relying party
 * authenticates the ACCESS token. A relying party that authenticates the ID
 * Token — `kubectl oidc-login` presents it, as do Grafana and Vault in that mode
 * — could not renew the credential it actually holds. Measured against a live
 * deployment: a client with a 300-second lifetime meant a browser window every
 * five minutes, which is the behaviour `offline_access` exists to prevent.
 */

/** The PKCE verifier every test in this file uses. */
const REFRESH_VERIFIER = 'a-sufficiently-long-code-verifier-1234567890';

/**
 * An authorization code carrying a nonce and a real authentication context —
 * `auth_time` and `amr` are the claims a refresh must not invent or lose.
 *
 * The client is made by the caller, because makeClient is a protected TestCase
 * method and only a test closure is bound to it.
 *
 * @param  list<string>  $scopes
 */
function refreshTestCode(string $clientId, array $scopes): string
{
    return app(AuthorizationCodes::class)->issue(
        $clientId,
        'user_42',
        'org_a',
        'https://app.test/cb',
        $scopes,
        Base64Url::encode(hash('sha256', REFRESH_VERIFIER, true)),
        'S256',
        'the-original-nonce',
        1_700_000_000,
        ['pwd', 'mfa'],
    );
}

/**
 * @param  list<string>  $scopes
 */
function exchangeCode(object $test, string $clientId, array $scopes): TestResponse
{
    return $test->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => refreshTestCode($clientId, $scopes),
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => REFRESH_VERIFIER,
    ])->assertOk();
}

function refreshWith(object $test, string $clientId, string $refreshToken): TestResponse
{
    return $test->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $clientId,
        'refresh_token' => $refreshToken,
    ])->assertOk();
}

/** The verified claims of a token, so every assertion here is on a SIGNED value. */
function refreshedClaims(string $jwt): TokenClaims
{
    return app(TokenSigner::class)->verify($jwt, [SigningAlg::RS256]);
}

it('returns an id_token from a refresh, so the credential a client presents can be renewed', function (): void {
    $clientId = $this->makeClient(
        ['openid', 'offline_access'],
        ClientType::Public,
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    )->client->client_id;

    $first = exchangeCode($this, $clientId, ['openid', 'offline_access']);

    $refreshed = refreshWith($this, $clientId, $first->json('refresh_token'));

    // THE WHOLE BUG: this was null, and a client authenticating the ID Token had
    // nothing to present once the first one expired.
    expect($refreshed->json('id_token'))->toBeString();

    $before = refreshedClaims($first->json('id_token'));
    $after = refreshedClaims($refreshed->json('id_token'));

    // OIDC Core §12.2: iss, sub and aud are the same as the original.
    expect($after->get('iss'))->toBe($before->get('iss'))
        ->and($after->get('iss'))->toBe(ServerMetadata::issuer())
        ->and($after->get('sub'))->toBe($before->get('sub'))
        ->and($after->get('sub'))->toBe('user_42')
        ->and($after->get('aud'))->toBe($before->get('aud'))
        ->and($after->get('aud'))->toBe($clientId);
});

it('stamps a new iat and binds at_hash to the NEW access token', function (): void {
    $clientId = $this->makeClient(
        ['openid', 'offline_access'],
        ClientType::Public,
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    )->client->client_id;

    $first = exchangeCode($this, $clientId, ['openid', 'offline_access']);

    $refreshed = refreshWith($this, $clientId, $first->json('refresh_token'));
    $after = refreshedClaims($refreshed->json('id_token'));

    // §12.2: iat is the time the NEW token is issued.
    expect($after->get('iat'))->toBeGreaterThanOrEqual(refreshedClaims($first->json('id_token'))->get('iat'));

    // And at_hash must bind the access token returned WITH it — a refreshed
    // id_token carrying the old token's hash is rejected by a strict relying
    // party, and would be a silent one to introduce by copying claims forward.
    $digest = hash('sha256', $refreshed->json('access_token'), true);
    expect($after->get('at_hash'))->toBe(Base64Url::encode(substr($digest, 0, intdiv(strlen($digest), 2))));
});

it('keeps auth_time and amr describing the ORIGINAL login', function (): void {
    $clientId = $this->makeClient(
        ['openid', 'offline_access'],
        ClientType::Public,
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    )->client->client_id;

    $first = exchangeCode($this, $clientId, ['openid', 'offline_access']);

    $refreshed = refreshWith($this, $clientId, $first->json('refresh_token'));
    $after = refreshedClaims($refreshed->json('id_token'));

    // §12.2 is explicit: auth_time describes when the user authenticated, not
    // when the token was refreshed. Re-stamping it would let a session look
    // freshly authenticated forever, which is exactly what a max_age check is
    // asking about.
    expect($after->get('auth_time'))->toBe(1_700_000_000)
        ->and($after->get('amr'))->toBe(['pwd', 'mfa'])
        // acr follows amr through the same enum, so an assurance level cannot
        // quietly drop at the first refresh.
        ->and($after->get('acr'))->toBe(refreshedClaims($first->json('id_token'))->get('acr'));
});

it('survives a second rotation, so the claims are carried and not merely echoed once', function (): void {
    $clientId = $this->makeClient(
        ['openid', 'offline_access'],
        ClientType::Public,
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    )->client->client_id;

    $first = exchangeCode($this, $clientId, ['openid', 'offline_access']);

    $second = refreshWith($this, $clientId, $first->json('refresh_token'));
    $third = refreshWith($this, $clientId, $second->json('refresh_token'));

    // The family carries the authentication, so the third token knows it too. A
    // value threaded only from the code exchange would be gone by now.
    expect(refreshedClaims($third->json('id_token'))->get('auth_time'))->toBe(1_700_000_000)
        ->and(refreshedClaims($third->json('id_token'))->get('amr'))->toBe(['pwd', 'mfa']);
});

it('does not echo the original nonce', function (): void {
    $clientId = $this->makeClient(
        ['openid', 'offline_access'],
        ClientType::Public,
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    )->client->client_id;

    $first = exchangeCode($this, $clientId, ['openid', 'offline_access']);

    expect(refreshedClaims($first->json('id_token'))->get('nonce'))->toBe('the-original-nonce');

    $refreshed = refreshWith($this, $clientId, $first->json('refresh_token'));

    // A nonce binds an id_token to one authentication REQUEST so the client can
    // detect replay. A refresh is not an authentication request, and handing back
    // a nonce the client has already seen is the condition its replay check
    // exists to catch.
    expect(refreshedClaims($refreshed->json('id_token'))->has('nonce'))->toBeFalse();
});

it('carries the groups a relying party binds authorization to', function (): void {
    $clientId = $this->makeClient(
        ['openid', 'offline_access', 'groups'],
        ClientType::Public,
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    )->client->client_id;

    $first = exchangeCode($this, $clientId, ['openid', 'offline_access', 'groups']);

    $role = app(Roles::class)->define('org_a', 'cluster-admin', null, $clientId);
    app(Roles::class)->assign('org_a', 'user_42', $role->id);

    $refreshed = refreshWith($this, $clientId, $first->json('refresh_token'));
    $after = refreshedClaims($refreshed->json('id_token'));

    // The case that forced ID Tokens to carry groups at all: Kubernetes maps a
    // claim to groups and binds RoleBindings to them. A refreshed token without
    // them authenticates the person and grants them nothing, which presents as a
    // permissions bug rather than a missing claim.
    expect($after->get('groups'))->toBe(['cluster-admin'])
        ->and($after->get('org'))->toBe('org_a');
});

it('gives a machine grant no id_token, because there is no one to assert', function (): void {
    $registered = $this->makeClient(
        ['api.read', 'offline_access'],
        grantTypes: ['client_credentials', 'refresh_token'],
    );

    $first = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'api.read offline_access',
    ])->assertOk();

    // client_credentials issues no refresh token at all, so there is nothing to
    // rotate — and if that ever changes, the guard below is what stops an ID
    // Token being minted for a grant with no subject behind it.
    expect($first->json('id_token'))->toBeNull();
});
