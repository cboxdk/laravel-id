<?php

declare(strict_types=1);

use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/** The PKCE verifier every test in this file uses. */
const VERIFIER = 'a-sufficiently-long-code-verifier-1234567890';

/**
 * Issue an authorization_code for an already-registered client (the caller makes
 * the client, since makeClient is a protected TestCase method).
 *
 * @param  list<string>  $scopes
 */
function issueCode(string $clientId, array $scopes): string
{
    return app(AuthorizationCodes::class)->issue(
        $clientId,
        'user_42',
        'org_a',
        'https://app.test/cb',
        $scopes,
        Base64Url::encode(hash('sha256', VERIFIER, true)),
        'S256',
        null,
        1_700_000_000,
        ['pwd', 'mfa'],
    );
}

it('binds the access token audience to the RFC 8707 resource', function (): void {
    $registered = $this->makeClient(['api.read'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'resource' => 'https://mcp.example.com',
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify($response->json('access_token'), [SigningAlg::RS256]);
    expect($claims->get('aud'))->toBe('https://mcp.example.com');
});

it('rejects a malformed RFC 8707 resource with invalid_target', function (): void {
    $registered = $this->makeClient(['api.read'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);

    // A relative/opaque value is not an absolute URI — the token must not be
    // issued unbound (which would over-scope it to every audience).
    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'resource' => 'not-a-uri',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');

    // A fragment is likewise forbidden by RFC 8707.
    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'resource' => 'https://mcp.example.com/#frag',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');
});

it('defaults aud to the issuer when no resource is requested (RFC 9068 requires aud on at+jwt)', function (): void {
    $registered = $this->makeClient(['api.read'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify($response->json('access_token'), [SigningAlg::RS256]);
    expect($claims->get('aud'))->toBe(ServerMetadata::issuer());
});

it('adds at_hash, auth_time, amr and acr to the id_token', function (): void {
    $clientId = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'])->client->client_id;
    $code = issueCode($clientId, ['openid']);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify($response->json('id_token'), [SigningAlg::RS256]);
    expect($claims->get('at_hash'))->toBeString()
        ->and($claims->get('auth_time'))->toBe(1_700_000_000)
        ->and($claims->get('amr'))->toBe(['pwd', 'mfa'])
        ->and($claims->get('acr'))->toBe('urn:cbox-id:aal2'); // mfa present -> level 2
});

it('issues a refresh token only when offline_access is granted', function (): void {
    $clientId = $this->makeClient(['openid', 'offline_access'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'])->client->client_id;
    $code = issueCode($clientId, ['openid', 'offline_access']);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->assertOk();

    expect($response->json('refresh_token'))->toBeString()->toStartWith('rt_');
});

it('does not issue a refresh token without offline_access', function (): void {
    $clientId = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'])->client->client_id;
    $code = issueCode($clientId, ['openid']);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->assertOk();

    expect($response->json('refresh_token'))->toBeNull();
});

it('rotates a refresh token and issues a fresh access token', function (): void {
    $clientId = $this->makeClient(['openid', 'offline_access'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'])->client->client_id;
    $code = issueCode($clientId, ['openid', 'offline_access']);

    $first = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->assertOk();

    $refresh = $first->json('refresh_token');

    $second = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $clientId,
        'refresh_token' => $refresh,
    ])->assertOk();

    expect($second->json('access_token'))->toBeString()
        ->and($second->json('refresh_token'))->toBeString()
        ->and($second->json('refresh_token'))->not->toBe($refresh); // rotated
});

it('detects refresh token reuse and revokes the whole family', function (): void {
    $clientId = $this->makeClient(['openid', 'offline_access'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'])->client->client_id;
    $code = issueCode($clientId, ['openid', 'offline_access']);

    $refresh = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->json('refresh_token');

    // First rotation succeeds and yields a successor.
    $next = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $refresh,
    ])->assertOk()->json('refresh_token');

    // Re-using the now-consumed original is theft -> invalid_grant.
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $refresh,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

    // ...and the family is dead, so the successor no longer works either.
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $next,
    ])->assertStatus(400);
});

it('serves RFC 8414 authorization server metadata', function (): void {
    // No host authorization_endpoint configured → the iss-param flag (a property of
    // that host-owned endpoint, RFC 9207) is honestly OMITTED, not asserted true.
    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('grant_types_supported', ['authorization_code', 'client_credentials', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code', 'urn:openid:params:grant-type:ciba', 'urn:ietf:params:oauth:grant-type:token-exchange'])
        ->assertJsonMissingPath('authorization_response_iss_parameter_supported')
        ->assertJsonStructure(['issuer', 'token_endpoint', 'jwks_uri', 'revocation_endpoint', 'code_challenge_methods_supported']);
});

it('advertises RFC 9207 iss-param only when the host authorization_endpoint is set', function (): void {
    config(['cbox-id.oauth.authorization_endpoint' => 'https://app.example.com/authorize']);

    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('authorization_response_iss_parameter_supported', true);
});

it('serves RFC 9728 protected resource metadata', function (): void {
    $this->getJson('/.well-known/oauth-protected-resource')
        ->assertOk()
        ->assertJsonStructure(['resource', 'authorization_servers', 'scopes_supported', 'bearer_methods_supported']);
});

it('returns userinfo for a valid bearer token with openid scope', function (): void {
    $registered = $this->makeClient(['openid', 'email', 'profile'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);
    $token = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid email profile',
    ])->json('access_token');

    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJsonStructure(['sub']);
});

it('refuses userinfo without a bearer token', function (): void {
    $this->getJson('/oauth/userinfo')->assertStatus(401);
});

it('revokes an access token via RFC 7009 for an authenticated client', function (): void {
    $registered = $this->makeClient(['api.read'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);
    $token = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])->json('access_token');

    // Token is active before revocation.
    $this->postJson('/oauth/introspect', [
        'token' => $token,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])->assertJsonPath('active', true);

    // Revoke, then it introspects as inactive.
    $this->postJson('/oauth/revoke', [
        'token' => $token,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])->assertOk();

    $this->postJson('/oauth/introspect', [
        'token' => $token,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])->assertJsonPath('active', false);
});

it('refuses revocation from an unauthenticated caller', function (): void {
    $this->postJson('/oauth/revoke', ['token' => 'whatever'])->assertStatus(401);
});

it('does not let one client introspect or revoke another client\'s token', function (): void {
    $owner = $this->makeClient(['api.read'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);
    $other = $this->makeClient(['api.read'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);

    $token = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $owner->client->client_id,
        'client_secret' => $owner->secret,
    ])->json('access_token');

    // A different client only ever sees active:false — no introspection oracle.
    $this->postJson('/oauth/introspect', [
        'token' => $token,
        'client_id' => $other->client->client_id,
        'client_secret' => $other->secret,
    ])->assertJsonPath('active', false);

    // And its revocation attempt is a no-op (still 200, no oracle).
    $this->postJson('/oauth/revoke', [
        'token' => $token,
        'client_id' => $other->client->client_id,
        'client_secret' => $other->secret,
    ])->assertOk();

    // The owner's token is untouched.
    $this->postJson('/oauth/introspect', [
        'token' => $token,
        'client_id' => $owner->client->client_id,
        'client_secret' => $owner->secret,
    ])->assertJsonPath('active', true);
});

it('does not let one client revoke another client\'s refresh-token family', function (): void {
    $owner = $this->makeClient(['openid', 'offline_access'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'])->client->client_id;
    $other = $this->makeClient(['api.read'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);
    $code = issueCode($owner, ['openid', 'offline_access']);

    $refresh = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $owner,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->json('refresh_token');

    // Another client can't revoke a family it doesn't own.
    $this->postJson('/oauth/revoke', [
        'token' => $refresh,
        'client_id' => $other->client->client_id,
        'client_secret' => $other->secret,
    ])->assertOk();

    // So the refresh token still rotates for its real owner.
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $owner,
        'refresh_token' => $refresh,
    ])->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
});
