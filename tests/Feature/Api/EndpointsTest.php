<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('serves the JWK Set', function (): void {
    $this->getJson('/.well-known/jwks.json')
        ->assertOk()
        ->assertJsonStructure(['keys']);
});

it('serves the OIDC discovery document', function (): void {
    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonStructure(['issuer', 'jwks_uri', 'token_endpoint', 'introspection_endpoint'])
        ->assertJsonPath('id_token_signing_alg_values_supported.0', 'RS256')
        ->assertJsonPath('code_challenge_methods_supported.0', 'S256')
        // Discovery polish: claims, ACRs, and response modes the OP actually honors.
        ->assertJsonPath('claims_supported', fn (array $c): bool => in_array('acr', $c, true) && in_array('org', $c, true))
        ->assertJsonPath('acr_values_supported', ['urn:cbox-id:aal1', 'urn:cbox-id:aal2'])
        // Honest advertisement: only `query` is served (never `fragment`).
        ->assertJsonPath('response_modes_supported', ['query']);
});

it('advertises only the id_token signing algs it actually holds keys for', function (): void {
    // The discovery `id_token_signing_alg_values_supported` must be exactly the algs
    // present in the JWKS — never an aspirational superset that a pinning client breaks
    // on. Provision the default RS256 signing key so the JWKS is populated.
    app(KeyManager::class)->rotate();

    $jwks = $this->getJson('/.well-known/jwks.json')->json('keys');
    $jwksAlgs = array_values(array_unique(array_column($jwks, 'alg')));

    $advertised = $this->getJson('/.well-known/openid-configuration')
        ->json('id_token_signing_alg_values_supported');

    sort($jwksAlgs);
    sort($advertised);

    expect($jwksAlgs)->toBe(['RS256'])           // fresh keystore: RS256 only
        ->and($advertised)->toBe($jwksAlgs)      // advertised == what the JWKS holds
        ->and($advertised)->not->toContain('ES256')
        ->and($advertised)->not->toContain('EdDSA');
});

it('omits authorization_endpoint when the host has not configured one', function (): void {
    // The package serves no /authorize route, so it must not advertise one.
    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonMissingPath('authorization_endpoint');
});

it('advertises the host authorization_endpoint when configured', function (): void {
    config(['cbox-id.oauth.authorization_endpoint' => 'https://app.example.com/authorize']);

    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('authorization_endpoint', 'https://app.example.com/authorize');
});

it('introspects an active token over HTTP for an authenticated caller', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);

    $this->postJson('/oauth/introspect', [
        'token' => $token->token,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])
        ->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonPath('sub', $registered->client->client_id)
        ->assertJsonPath('scope', 'api.read')
        // RFC 7662 §2.2: the response surfaces the token's type and lifetime.
        ->assertJsonPath('token_type', 'Bearer')
        ->assertJsonPath('iss', fn (mixed $v): bool => is_string($v) && $v !== '')
        ->assertJsonPath('exp', fn (mixed $v): bool => is_int($v) && $v > time())
        ->assertJsonPath('iat', fn (mixed $v): bool => is_int($v));
});

it('accepts HTTP Basic client authentication on introspection', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);

    $this->postJson('/oauth/introspect', ['token' => $token->token], [
        'Authorization' => 'Basic '.base64_encode($registered->client->client_id.':'.$registered->secret),
    ])
        ->assertOk()
        ->assertJsonPath('active', true);
});

it('refuses introspection from an unauthenticated caller', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);

    // No client credentials — the endpoint must not act as an open token oracle.
    $this->postJson('/oauth/introspect', ['token' => $token->token])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

it('refuses introspection with a wrong client secret', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);

    $this->postJson('/oauth/introspect', [
        'token' => $token->token,
        'client_id' => $registered->client->client_id,
        'client_secret' => 'wrong-secret',
    ])->assertStatus(401);
});

it('reports a bad token as inactive for an authenticated caller', function (): void {
    $registered = $this->makeClient(['api.read']);

    $this->postJson('/oauth/introspect', [
        'token' => 'garbage',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])
        ->assertOk()
        ->assertJsonPath('active', false);
});

it('responds to the health probe', function (): void {
    $this->getJson('/up')->assertOk();
});

/**
 * A single absolute authorization_endpoint pins every environment to one host. Because
 * RFC 9207 (`iss` on the authorization response) is advertised alongside it, a
 * mix-up-hardened RP — node openid-client v5+, Spring Security 6, AppAuth, any FAPI
 * client — then compares the callback's `iss` against discovery and aborts the login.
 * The path form derives from the per-environment issuer instead.
 */
it('derives authorization_endpoint from the per-environment issuer', function (): void {
    config(['cbox-id.oauth.authorization_endpoint_path' => '/oauth/authorize']);

    $document = $this->getJson('/.well-known/openid-configuration')->assertOk()->json();

    expect($document['authorization_endpoint'])->toBe($document['issuer'].'/oauth/authorize')
        ->and($document['authorization_response_iss_parameter_supported'])->toBeTrue();
});

it('prefers the path form over a fixed absolute endpoint', function (): void {
    config([
        'cbox-id.oauth.authorization_endpoint' => 'https://apex.example.com/authorize',
        'cbox-id.oauth.authorization_endpoint_path' => '/oauth/authorize',
    ]);

    $document = $this->getJson('/.well-known/openid-configuration')->assertOk()->json();

    expect($document['authorization_endpoint'])->toBe($document['issuer'].'/oauth/authorize');
});

/**
 * The regression guard that makes the omission visible to CI. authorization_endpoint is
 * REQUIRED by OpenID Connect Discovery 1.0 §3, and every conformant client throws at
 * discover() before a single redirect when it is missing — which is what a
 * docs-following deployment served.
 */
it('serves every field OpenID Connect Discovery marks REQUIRED', function (): void {
    config(['cbox-id.oauth.authorization_endpoint_path' => '/oauth/authorize']);

    $document = $this->getJson('/.well-known/openid-configuration')->assertOk()->json();

    $required = [
        'issuer',
        'authorization_endpoint',
        'token_endpoint',
        'jwks_uri',
        'response_types_supported',
        'subject_types_supported',
        'id_token_signing_alg_values_supported',
    ];

    $missing = array_values(array_diff($required, array_keys($document)));

    expect($missing)->toBe([], 'Discovery is missing REQUIRED field(s): '.implode(', ', $missing));
});
