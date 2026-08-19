<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\OAuthServer\Contracts\DynamicClientRegistration;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function openDcr(): void
{
    config(['cbox-id.oauth.dynamic_registration.mode' => 'open']);
}

it('refuses registration when DCR is disabled (secure by default)', function (): void {
    config(['cbox-id.oauth.dynamic_registration.mode' => 'disabled']);

    $this->postJson('/oauth/register', [
        'client_name' => 'MCP Client',
        'redirect_uris' => ['https://app.test/cb'],
    ])
        ->assertStatus(403)
        ->assertJsonPath('error', 'access_denied');
});

it('registers a public client via RFC 7591 and returns a registration access token', function (): void {
    openDcr();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'MCP CLI',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['http://127.0.0.1:8765/callback'],
        'scope' => 'openid profile email',
    ])->assertStatus(201);

    $response
        ->assertJsonPath('token_endpoint_auth_method', 'none')
        ->assertJsonPath('client_name', 'MCP CLI')
        ->assertJsonPath('grant_types', ['authorization_code'])
        ->assertJsonPath('redirect_uris', ['http://127.0.0.1:8765/callback'])
        ->assertJsonStructure(['client_id', 'client_id_issued_at', 'registration_access_token', 'registration_client_uri']);

    // Public clients get no secret.
    expect($response->json('client_secret'))->toBeNull()
        ->and(Client::query()->where('client_id', $response->json('client_id'))->exists())->toBeTrue();
});

it('registers a confidential client with a secret when auth method is not none', function (): void {
    openDcr();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Backend service',
        'grant_types' => ['client_credentials'],
        'scope' => 'openid',
    ])->assertStatus(201);

    expect($response->json('client_secret'))->toBeString()
        ->and($response->json('client_secret_expires_at'))->toBe(0);
});

it('reduces requested scopes to the configured allow-list', function (): void {
    openDcr();
    config(['cbox-id.oauth.dynamic_registration.allowed_scopes' => ['openid', 'email']]);

    $response = $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
        'scope' => 'openid email admin superuser',
    ])->assertStatus(201);

    expect($response->json('scope'))->toBe('openid email');
});

/**
 * `organizations` is advertised in `scopes_supported` and the token/UserInfo layer
 * emits the claim, but it was missing from the default allow-list — so a
 * dynamically-registered client could never obtain it. Advertised and unreachable.
 */
it('lets a dynamically registered client obtain every advertised sign-in scope', function (): void {
    openDcr();

    $response = $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
        'scope' => 'openid profile email offline_access organizations',
    ])->assertStatus(201);

    expect($response->json('scope'))->toBe('openid profile email offline_access organizations');
});

it('accepts plain-http redirect URIs on any host only in a sandbox environment', function (): void {
    openDcr();
    $registrar = app(DynamicClientRegistration::class);
    $metadata = [
        'client_name' => 'Dev App',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['http://app.test/cb'],
    ];

    // Production: plain http on a non-loopback host is refused.
    $prod = Environment::query()->create(['name' => 'Prod', 'slug' => 'p', 'type' => EnvironmentType::Production, 'status' => 'active']);
    app(EnvironmentContext::class)->set($prod);
    expect(fn () => $registrar->validate($metadata))->toThrow(InvalidClientMetadata::class);

    // Sandbox: the same redirect_uri is accepted for local development.
    $sandbox = Environment::query()->create(['name' => 'Sandbox', 'slug' => 's', 'type' => EnvironmentType::Sandbox, 'status' => 'active']);
    app(EnvironmentContext::class)->set($sandbox);
    expect($registrar->validate($metadata)->redirectUris)->toBe(['http://app.test/cb']);
});

it('rejects a redirect_uri that is not https or loopback', function (): void {
    openDcr();

    $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['http://evil.test/cb'],
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_redirect_uri');
});

it('registers a native app with private-use URI scheme redirects (both forms)', function (): void {
    openDcr();

    // RFC 8252 §7.1 — a native app registers a custom scheme in either the
    // authority form (com.example.app://cb) or the canonical path form
    // (com.example.app:/cb). Both must be accepted (AppAuth defaults to the latter).
    $uris = ['com.example.app://oauth2redirect', 'com.example.app:/oauth2redirect'];

    $this->postJson('/oauth/register', [
        'client_name' => 'iOS app',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => $uris,
    ])
        ->assertStatus(201)
        ->assertJsonPath('redirect_uris', $uris)
        ->assertJsonPath('token_endpoint_auth_method', 'none');
});

it('rejects a dangerous or dotless custom redirect scheme', function (): void {
    openDcr();

    // A single-word scheme a browser may execute (javascript:/data:/file:) or a
    // non-reverse-domain custom scheme (app:) must never register — the former would
    // become stored XSS in the AS origin, the latter violates RFC 8252 §7.1.
    foreach (['javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd', 'app:/cb'] as $uri) {
        $this->postJson('/oauth/register', [
            'token_endpoint_auth_method' => 'none',
            'grant_types' => ['authorization_code'],
            'redirect_uris' => [$uri],
        ])
            ->assertStatus(400)
            ->assertJsonPath('error', 'invalid_redirect_uri');
    }
});

it('rejects a redirect_uri containing a fragment', function (): void {
    openDcr();

    $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb#frag'],
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_redirect_uri');
});

it('requires redirect_uris for the authorization_code grant', function (): void {
    openDcr();

    $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_redirect_uri');
});

it('rejects a grant_type outside the allow-list', function (): void {
    openDcr();

    $this->postJson('/oauth/register', [
        'grant_types' => ['password'],
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');
});

it('rejects a public client asking for client_credentials', function (): void {
    openDcr();

    $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['client_credentials'],
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');
});

it('gates protected mode on the initial access token', function (): void {
    config([
        'cbox-id.oauth.dynamic_registration.mode' => 'protected',
        'cbox-id.oauth.dynamic_registration.initial_access_token' => 'iat-secret-123',
    ]);

    // No token → 401.
    $this->postJson('/oauth/register', ['grant_types' => ['client_credentials']])
        ->assertStatus(401);

    // Correct token → 201.
    $this->withHeader('Authorization', 'Bearer iat-secret-123')
        ->postJson('/oauth/register', ['grant_types' => ['client_credentials']])
        ->assertStatus(201);
});

it('reads and deletes a client via the RFC 7592 registration access token', function (): void {
    openDcr();

    $created = $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
    ])->assertStatus(201);

    $clientId = $created->json('client_id');
    $regToken = $created->json('registration_access_token');
    $auth = ['Authorization' => 'Bearer '.$regToken];

    // Read.
    $this->getJson('/oauth/register/'.$clientId, $auth)
        ->assertOk()
        ->assertJsonPath('client_id', $clientId);

    // Wrong token is refused.
    $this->getJson('/oauth/register/'.$clientId, ['Authorization' => 'Bearer wrong'])
        ->assertStatus(401);

    // Delete, then it is gone.
    $this->deleteJson('/oauth/register/'.$clientId, [], $auth)->assertNoContent();
    expect(Client::query()->where('client_id', $clientId)->exists())->toBeFalse();
});

it('advertises the registration endpoint in discovery only when enabled', function (): void {
    config(['cbox-id.oauth.dynamic_registration.mode' => 'disabled']);
    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonMissingPath('registration_endpoint');

    config(['cbox-id.oauth.dynamic_registration.mode' => 'open']);
    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('registration_endpoint', rtrim(url('/'), '/').'/oauth/register');
});

/**
 * The registration door and the metadata document have to agree about what this server
 * accepts.
 *
 * They did not. `token_endpoint_auth_methods_supported` advertised `private_key_jwt` at
 * the token, revocation and introspection endpoints; `DynamicClientRegistrar::AUTH_METHODS`
 * listed three methods and not that one, so registering with it returned
 * `400 unsupported token_endpoint_auth_method`. The capability behind the door was
 * complete the whole time — `ClientAuthenticator` verifies the assertion, `ClientRegistry`
 * stores a JWK Set and deliberately issues no secret alongside it. Only the way in was
 * shut, and the document said otherwise.
 */
it('accepts every auth method its own discovery document advertises', function (): void {
    openDcr();

    $advertised = $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->json('token_endpoint_auth_methods_supported');

    expect($advertised)->toBeArray()->not->toBeEmpty();

    foreach ($advertised as $method) {
        // `none` cannot take client_credentials and private_key_jwt needs its keys — the
        // point is that none of them is refused AS A METHOD.
        $body = [
            'client_name' => 'Conformance probe '.$method,
            'token_endpoint_auth_method' => $method,
            'grant_types' => ['authorization_code'],
            'redirect_uris' => ['https://app.test/cb'],
        ];

        if ($method === 'private_key_jwt') {
            $body['jwks'] = ['keys' => [['kty' => 'RSA', 'kid' => 'k1', 'n' => 'abc', 'e' => 'AQAB']]];
        }

        $response = $this->postJson('/oauth/register', $body);

        expect($response->status())->toBe(
            201,
            "discovery advertises {$method} and registration refused it: ".(string) $response->getContent(),
        );
    }
});

it('registers a private_key_jwt client with its keys, and issues no secret', function (): void {
    openDcr();

    $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'k1', 'n' => 'abc', 'e' => 'AQAB']]];

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Assertion client',
        'token_endpoint_auth_method' => 'private_key_jwt',
        'grant_types' => ['client_credentials'],
        'jwks' => $jwks,
    ])->assertStatus(201);

    // The document tells the truth about how to authenticate. It used to answer
    // `client_secret_basic` for every confidential client — including this one, which
    // holds no secret to put in a Basic header.
    $response->assertJsonPath('token_endpoint_auth_method', 'private_key_jwt')
        ->assertJsonPath('jwks', $jwks)
        ->assertJsonMissingPath('client_secret');

    $client = Client::query()->where('client_id', $response->json('client_id'))->firstOrFail();

    // `toEqual`, NOT `toBe`. MySQL 8 stores a JSON column as a parsed document and
    // normalises object key order on the way back out, so a round-tripped key set returns
    // the same pairs in a different order. `toBe` is `===`, which for arrays means same
    // order as well — so this passed on sqlite and Postgres, which round-trip the text
    // verbatim, and failed only on the MySQL leg of the engine matrix. What is under test
    // is which keys were stored, never what order they came back in.
    expect($client->jwks)->toEqual($jwks)
        // One credential mechanism, not two.
        ->and($client->secret_hash)->toBeNull();
});

it('refuses a private_key_jwt registration with no keys, rather than minting a client that can never authenticate', function (): void {
    openDcr();

    $this->postJson('/oauth/register', [
        'client_name' => 'Keyless',
        'token_endpoint_auth_method' => 'private_key_jwt',
        'grant_types' => ['client_credentials'],
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_client_metadata');
});

/**
 * `jwks_uri` is refused OUT LOUD.
 *
 * Accepting it would have the server fetch a URL the registrant chose, from an endpoint
 * that is unauthenticated in `open` mode — SSRF handed out by a public API. Dropping it
 * silently would be worse in a quieter way: the client registers, believes its keys are
 * on file, and every assertion it signs is rejected with nothing anywhere saying why.
 */
it('refuses jwks_uri instead of silently ignoring it', function (): void {
    openDcr();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Remote keys',
        'token_endpoint_auth_method' => 'private_key_jwt',
        'grant_types' => ['client_credentials'],
        'jwks_uri' => 'https://app.test/jwks.json',
    ])->assertStatus(400);

    expect((string) $response->json('error_description'))->toContain('jwks_uri');
});

/**
 * What a client registers as is what it reads back as.
 *
 * `token_endpoint_auth_method` was never stored. Readback INFERRED it from the client's
 * type and whether it had a JWK Set, and the inference has only three answers, so a client
 * that registered `client_secret_post` was told on every read that it was
 * `client_secret_basic`. RFC 7592 §3 calls the read the client's current registration; a
 * conformant client that reconciles its config against it either rewrites itself to the
 * wrong method or reports drift forever.
 *
 * The registration test above proves each advertised method is ACCEPTED. That is a
 * different claim, and it stayed green through the whole time this was wrong.
 */
it('reads back the exact auth method a client registered with', function (string $method, array $extra): void {
    openDcr();

    $created = $this->postJson('/oauth/register', array_merge([
        'client_name' => 'Readback '.$method,
        'token_endpoint_auth_method' => $method,
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
    ], $extra))->assertStatus(201);

    expect($created->json('token_endpoint_auth_method'))->toBe($method);

    $this->getJson('/oauth/register/'.$created->json('client_id'), [
        'Authorization' => 'Bearer '.$created->json('registration_access_token'),
    ])->assertOk()->assertJsonPath('token_endpoint_auth_method', $method);
})->with([
    'basic' => ['client_secret_basic', []],
    'post' => ['client_secret_post', []],
    'none' => ['none', []],
    'private_key_jwt' => ['private_key_jwt', ['jwks' => ['keys' => [['kty' => 'RSA', 'kid' => 'k1', 'n' => 'abc', 'e' => 'AQAB']]]]],
]);
