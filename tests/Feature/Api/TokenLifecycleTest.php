<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\RefreshToken;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

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

it('derives at_hash as the base64url LEFT HALF of the access token SHA-256 (OIDC Core 3.1.3.6)', function (): void {
    $clientId = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code'])->client->client_id;
    $code = issueCode($clientId, ['openid']);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->assertOk();

    $accessToken = $response->json('access_token');
    $idToken = $response->json('id_token');
    $atHash = app(TokenSigner::class)->verify($idToken, [SigningAlg::RS256])->get('at_hash');

    // Spelled out from the spec rather than taken from the implementation: for an
    // RS256 id_token the hash is SHA-256 and at_hash is the base64url of its LEFT
    // 128 bits. Asserting only ->toBeString() would pass for the full 32-byte digest,
    // for the right half, or for a hash of the id_token — each of which a strict RP
    // rejects, failing every login while this suite stays green.
    $digest = hash('sha256', (string) $accessToken, true);

    expect($atHash)->toBe(Base64Url::encode(substr($digest, 0, 16)))
        // 128 bits base64url = 22 chars unpadded; the full digest would be 43.
        ->and($atHash)->toHaveLength(22)
        // Explicitly NOT the whole digest, NOT the right half, NOT the id_token's hash.
        ->and($atHash)->not->toBe(Base64Url::encode($digest))
        ->and($atHash)->not->toBe(Base64Url::encode(substr($digest, 16, 16)))
        ->and($atHash)->not->toBe(Base64Url::encode(substr(hash('sha256', (string) $idToken, true), 0, 16)));
});

/**
 * RFC 7636 Appendix B publishes one S256 pair. id-js and id-python both assert the
 * client-side derivation against it; until now nothing proved the SERVER accepts
 * that exact pair. Every other exchange in this suite either invents a verifier and
 * hashes it with the same code the server compares against, or (in
 * PushedAuthorizationTest) carries the challenge as an opaque string never paired
 * with its verifier — so a base64url or padding regression in the server's
 * comparison would reject every conforming client with the suite still green.
 */
const RFC7636_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC7636_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

it('accepts the RFC 7636 Appendix B verifier against its published challenge', function (): void {
    $clientId = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code'])->client->client_id;

    // The challenge is stored exactly as the RFC prints it — no local derivation.
    $code = app(AuthorizationCodes::class)->issue(
        $clientId,
        'user_42',
        'org_a',
        'https://app.test/cb',
        ['openid'],
        RFC7636_CHALLENGE,
        'S256',
    );

    $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => RFC7636_VERIFIER,
    ])->assertOk()->assertJsonStructure(['access_token', 'id_token']);
});

it('rejects any verifier other than the RFC 7636 Appendix B one for its challenge', function (): void {
    $clientId = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code'])->client->client_id;

    // Same-length, same-alphabet, one character different — the comparison must be
    // over the hash, not a prefix or a length check.
    $tampered = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXj';

    $code = app(AuthorizationCodes::class)->issue(
        $clientId, 'user_42', 'org_a', 'https://app.test/cb', ['openid'], RFC7636_CHALLENGE, 'S256',
    );

    $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $tampered,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('does not accept the RFC 7636 challenge as its own verifier under S256', function (): void {
    // A server that compared the raw values (or fell back to `plain`) would accept
    // this — and would then accept any intercepted challenge as proof of possession,
    // defeating PKCE entirely.
    $clientId = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code'])->client->client_id;

    $code = app(AuthorizationCodes::class)->issue(
        $clientId, 'user_42', 'org_a', 'https://app.test/cb', ['openid'], RFC7636_CHALLENGE, 'S256',
    );

    $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => RFC7636_CHALLENGE,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
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

    // Age the consumed original past the concurrency grace window so re-presenting it
    // is treated as genuine theft, not a benign parallel refresh.
    RefreshToken::query()->whereNotNull('consumed_at')->update(['consumed_at' => now()->subMinute()]);

    // Re-using the now-consumed original is theft -> invalid_grant.
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $refresh,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

    // ...and the family is dead, so the successor no longer works either.
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $next,
    ])->assertStatus(400);
});

it('returns the SAME successor for a concurrent double-refresh within the grace window (idempotent, no second live token)', function (): void {
    $clientId = $this->makeClient(['openid', 'offline_access'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'])->client->client_id;
    $code = issueCode($clientId, ['openid', 'offline_access']);

    $refresh = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code', 'client_id' => $clientId, 'code' => $code,
        'redirect_uri' => 'https://app.test/cb', 'code_verifier' => VERIFIER,
    ])->json('refresh_token');

    // First rotation consumes the token and yields a successor.
    $first = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $refresh,
    ])->assertOk()->json('refresh_token');

    // A parallel request presenting the SAME token immediately (within grace) gets the
    // IDENTICAL successor — not a second, independent live token. This is the fix: a
    // stolen token replayed in the window can never yield its own lineage. Concurrency
    // is still tolerated (no family revocation), it just converges on one successor.
    $second = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $refresh,
    ])->assertOk()->json('refresh_token');

    expect($first)->toBeString()->and($second)->toBe($first);

    // The family was NOT revoked: the single successor still rotates.
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $first,
    ])->assertOk();

    // And across the whole family only ONE token was ever live at a time — never two
    // siblings. (Raw query to bypass the deny-by-default env scope outside a request.)
    $liveCount = DB::table('oauth_refresh_tokens')
        ->whereNull('consumed_at')
        ->whereNull('revoked_at')
        ->count();
    expect($liveCount)->toBe(1);
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

it('refuses userinfo for a token audienced for another resource (RFC 8707)', function (): void {
    $registered = $this->makeClient(['openid', 'email', 'profile'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);
    $token = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid email profile',
        'resource' => 'https://mcp.example.com',
    ])->json('access_token');

    // The token's aud is the MCP resource, not this issuer — it must not be
    // replayable at UserInfo to harvest identity claims.
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$token])
        ->assertStatus(401);
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

/**
 * A client must not be able to choose the audience after the fact.
 *
 * `resource` was read at the token endpoint, checked for being an absolute URI, and
 * stamped verbatim into `aud` — while nothing recorded what the user had authorized. So
 * any client holding a valid code could name any audience at redemption and receive a
 * token asserting it, signed by us. That is a confused deputy against every resource
 * server that trusts this issuer and checks `aud`, which is exactly the check RFC 9068
 * tells it to make and the property the MCP authorization model rests on.
 *
 * RFC 8707 §2.2: the token request's resource must be the one the authorization was
 * granted for.
 */
it('refuses a redemption that asks for a different resource than was authorized', function (): void {
    $registered = $this->makeClient(['api.read'], grantTypes: ['authorization_code']);

    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user_42',
        'org_a',
        'https://app.test/cb',
        ['api.read'],
        Base64Url::encode(hash('sha256', VERIFIER, true)),
        'S256',
        null,
        1_700_000_000,
        ['pwd'],
        'https://mcp.acme.example',
    );

    $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
        'resource' => 'https://api.someone-else.example',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');
});

it('mints the authorized audience even when the redemption names none', function (): void {
    $registered = $this->makeClient(['api.read'], grantTypes: ['authorization_code']);

    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user_42',
        'org_a',
        'https://app.test/cb',
        ['api.read'],
        Base64Url::encode(hash('sha256', VERIFIER, true)),
        'S256',
        null,
        1_700_000_000,
        ['pwd'],
        'https://mcp.acme.example',
    );

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify($response->json('access_token'), [SigningAlg::RS256]);

    expect($claims->get('aud'))->toBe('https://mcp.acme.example');
});

/**
 * Kubernetes authenticates the ID TOKEN, and ours carried no groups.
 *
 * `kubectl oidc-login` presents the id_token as its bearer and the API server maps a
 * claim to groups — while our roles lived only on the access token. A cluster could
 * therefore authenticate a person and have nothing to bind a RoleBinding to: every
 * request denied, with the identity plainly correct in the logs.
 *
 * Behind a scope, so no existing client's id_token changes shape.
 */
it('puts this app roles on the id_token when the groups scope is granted', function (): void {
    $registered = $this->makeClient(['openid', 'groups'], grantTypes: ['authorization_code']);

    grantRole($registered->client->client_id, 'user_42', 'org_a', 'cluster-admin');

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'code' => issueCodeWithScopes($registered->client->client_id, ['openid', 'groups']),
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify($response->json('id_token'), [SigningAlg::RS256]);

    expect($claims->get('groups'))->toBe(['cluster-admin']);
});

it('leaves the id_token unchanged for a client that did not ask for groups', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['authorization_code']);

    grantRole($registered->client->client_id, 'user_42', 'org_a', 'cluster-admin');

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'code' => issueCodeWithScopes($registered->client->client_id, ['openid']),
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify($response->json('id_token'), [SigningAlg::RS256]);

    expect($claims->get('groups'))->toBeNull();
});

/**
 * A credential a resource server validates OFFLINE can only be revoked by expiry, so its
 * TTL is its revocation window. One deployment-wide value cannot serve both a kubectl
 * credential (minutes) and a browser session (longer) — this is the per-client override.
 */
it('mints access tokens at the client own TTL', function (): void {
    $short = $this->makeClient(['api.read'], grantTypes: ['client_credentials'], accessTokenTtl: 300);
    $default = $this->makeClient(['api.read'], grantTypes: ['client_credentials']);

    $shortResponse = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $short->client->client_id,
        'client_secret' => $short->secret,
    ])->assertOk();

    $defaultResponse = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $default->client->client_id,
        'client_secret' => $default->secret,
    ])->assertOk();

    expect($shortResponse->json('expires_in'))->toBe(300)
        ->and($defaultResponse->json('expires_in'))->toBe(900, 'a client without its own TTL stopped using the deployment default');

    $claims = app(TokenSigner::class)->verify($shortResponse->json('access_token'), [SigningAlg::RS256]);

    expect($claims->get('exp') - $claims->get('iat'))->toBe(300, 'expires_in and the token exp disagreed');
});

/**
 * A code carrying an explicit scope set — the id_token claims depend on what was granted,
 * not on what the client is registered for.
 *
 * @param  list<string>  $scopes
 */
function issueCodeWithScopes(string $clientId, array $scopes): string
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
        ['pwd'],
    );
}

/** Give a subject a role this client can see, through the real access-control path. */
function grantRole(string $clientId, string $userId, string $organizationId, string $role): void
{
    $defined = app(Roles::class)->define($organizationId, $role);
    app(Roles::class)->assign($organizationId, $userId, $defined->id);
}

/**
 * A client's lifetime has to reach the token it actually presents.
 *
 * `kubectl oidc-login` presents the ID TOKEN as its bearer, and Kubernetes
 * validates `exp` offline and never calls back — so for that relying party the
 * id_token's lifetime IS the revocation window. While this was hardcoded at 900,
 * registering the kubectl client with a 300-second TTL shortened a credential it
 * never sends and left the one it does at fifteen minutes.
 */
it('gives the id_token the client lifetime, not a hardcoded one', function (): void {
    $clientId = $this->makeClient(
        ['openid'],
        ClientType::Public,
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
        accessTokenTtl: 300,
    )->client->client_id;

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => issueCode($clientId, ['openid']),
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify($response->json('id_token'), [SigningAlg::RS256]);

    // The SIGNED claims, not `expires_in`: the response field describes the
    // access token, and a change that moved only one of them would look right in
    // the response and be wrong in the credential.
    expect($claims->get('exp') - $claims->get('iat'))->toBe(300)
        ->and($response->json('expires_in'))->toBe(300);
});

it('leaves the id_token at the deployment default when a client asks for nothing', function (): void {
    $clientId = $this->makeClient(
        ['openid'],
        ClientType::Public,
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    )->client->client_id;

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => issueCode($clientId, ['openid']),
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify($response->json('id_token'), [SigningAlg::RS256]);

    // Unchanged for everybody who has not asked for something else.
    expect($claims->get('exp') - $claims->get('iat'))->toBe(900);
});

it('follows a configured deployment default too', function (): void {
    config()->set('cbox-id.oauth.access_token_ttl', 120);

    $clientId = $this->makeClient(
        ['openid'],
        ClientType::Public,
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    )->client->client_id;

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => issueCode($clientId, ['openid']),
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => VERIFIER,
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify($response->json('id_token'), [SigningAlg::RS256]);

    expect($claims->get('exp') - $claims->get('iat'))->toBe(120);
});

/**
 * A PUBLIC CLIENT MUST BE ABLE TO REVOKE ITS OWN TOKENS.
 *
 * Sign-out in every mainstream browser SDK — AppAuth-JS, oidc-client-ts with
 * `revokeTokensOnSignout`, angular-auth-oidc-client — posts the refresh token here. A
 * PKCE client authenticates with `none` and so holds no secret, and this endpoint
 * required one: the answer was `401 invalid_client`, the SDK swallowed it, and the
 * refresh token stayed valid for its whole lifetime after the person pressed sign out.
 *
 * Our own discovery document advertises `none` as a supported client-authentication
 * method, so the client had every reason to expect this to work.
 */
it('lets a public client revoke its own refresh token, with no secret', function (): void {
    $registered = $this->makeClient(
        ['api.read', 'offline_access'],
        ClientType::Public,
        grantTypes: ['authorization_code', 'refresh_token'],
    );

    $refresh = app(RefreshTokens::class)->issue(
        $registered->client,
        'user-public-revoke',
        null,
        ['api.read', 'offline_access'],
    );

    $this->postJson('/oauth/revoke', [
        'token' => $refresh,
        'client_id' => $registered->client->client_id,
    ])->assertOk();

    // And it is genuinely gone: redeeming it now fails.
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'refresh_token' => $refresh,
        'client_id' => $registered->client->client_id,
    ])->assertStatus(400);
});

/**
 * And the metadata says so, per endpoint. A client had to discover the difference between
 * revocation and introspection by trying, and the answer to trying was a 401 nobody sees.
 */
it('advertises which client authentication each token endpoint accepts', function (): void {
    $metadata = $this->getJson('/.well-known/openid-configuration')->json();

    expect($metadata['revocation_endpoint_auth_methods_supported'])->toContain('none')
        // Introspection answers questions about a token rather than destroying one, so
        // an unauthenticated caller there is an oracle. It must NOT offer `none`.
        ->and($metadata['introspection_endpoint_auth_methods_supported'])->not->toContain('none');
});

/**
 * AN ID TOKEN IS FOR A CLIENT THAT ASKED WHO THIS IS.
 *
 * Every user-present branch of the token endpoint minted one regardless of scope, so a
 * client that requested `api.read` and nothing else was handed a signed assertion
 * carrying `sub` and `org` — a subject identifier and a tenant, to an OAuth-only client
 * that never asked for identity. UserInfo has always refused that same client for the
 * same reason, so the endpoint contradicted itself about who is entitled to an identity
 * claim.
 */
it('returns no id_token when openid was not granted', function (): void {
    $registered = $this->makeClient(['api.read'], grantTypes: ['authorization_code']);

    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user-no-openid',
        null,
        'https://app.test/cb',
        ['api.read'],
        Base64Url::encode(hash('sha256', 'a-verifier-of-sufficient-length-0123456789abc', true)),
    );

    $body = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'code_verifier' => 'a-verifier-of-sufficient-length-0123456789abc',
    ])->assertOk()->json();

    expect($body)->toHaveKey('access_token')
        ->and($body)->not->toHaveKey('id_token');
});

/** And the client that DOES ask still gets one. */
it('returns an id_token when openid was granted', function (): void {
    $registered = $this->makeClient(['openid', 'api.read'], grantTypes: ['authorization_code']);

    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user-openid',
        null,
        'https://app.test/cb',
        ['openid', 'api.read'],
        Base64Url::encode(hash('sha256', 'a-verifier-of-sufficient-length-0123456789abc', true)),
    );

    $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'code_verifier' => 'a-verifier-of-sufficient-length-0123456789abc',
    ])->assertOk()->assertJsonStructure(['access_token', 'id_token']);
});
