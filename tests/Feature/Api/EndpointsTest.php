<?php

declare(strict_types=1);

use Cbox\Id\Api\Http\Controllers\TokenController;
use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Cbox\Id\OAuthServer\ClientAssertion\ClientAssertionValidator;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Dpop\DpopProofValidator;
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

/**
 * THE PROPERTY IS "what id_tokens are signed with", NOT "what keys exist".
 *
 * Discovery derives `id_token_signing_alg_values_supported` from the keystore, while
 * `TokenController::ID_TOKEN_ALG` pins every id_token to RS256. On a keystore that holds
 * only ES256 the document promises ES256 and the id_token arrives RS256, so a conformant
 * relying party that pinned the advertised alg rejects it.
 *
 * AND IT SELF-HEALS, which is what makes it expensive to diagnose rather than obvious:
 * `activeSigningKey()` is `$existing ?? $this->generate($alg)`, so issuance does not fail
 * — it silently mints an RS256 key on first use. From the second request onward discovery
 * advertises both algs and the symptom disappears, leaving one rejected login and nothing
 * to look at.
 *
 * The test below this one asserted `advertised == jwks` — the divergence itself, stated as
 * the invariant. It passed because the fixture only ever holds RS256, so all three values
 * coincide and the case where they differ was never constructed.
 */
it('advertises the alg id_tokens are actually signed with, not merely the keys it holds', function (): void {
    // A keystore with no RS256 key at all: the shape a deployment lands in by rotating to
    // ES256, which the key manager supports and nothing forbids.
    app(KeyManager::class)->rotate(SigningAlg::ES256);
    SigningKey::query()->where('alg', SigningAlg::RS256->value)->delete();

    $advertised = $this->getJson('/.well-known/openid-configuration')
        ->json('id_token_signing_alg_values_supported');

    // RS256 is what an id_token will be signed with here, whatever keys are present, so
    // it is what a relying party must be told to expect.
    expect($advertised)->toContain('RS256');
});

/**
 * The other half: the list is not an aspirational superset either.
 *
 * This used to assert `advertised == jwksAlgs` and called that the invariant. It was the
 * divergence written down as a rule, and it passed only because the fixture holds RS256
 * and nothing else, so keystore, advertisement and signature all coincided. The case that
 * distinguishes them — a keystore without RS256 — is the test above.
 */
it('advertises exactly one id_token alg, whatever else the keystore holds', function (): void {
    // A second alg in the keystore, which the JWKS must expose (other credentials use it)
    // and which this list must NOT pick up (no id_token is ever signed with it).
    app(KeyManager::class)->rotate();
    app(KeyManager::class)->rotate(SigningAlg::ES256);

    $jwksAlgs = array_values(array_unique(array_column(
        $this->getJson('/.well-known/jwks.json')->json('keys'), 'alg',
    )));

    $advertised = $this->getJson('/.well-known/openid-configuration')
        ->json('id_token_signing_alg_values_supported');

    expect($jwksAlgs)->toContain('ES256')
        ->and($advertised)->toBe(['RS256']);
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

/**
 * EVERY ALGORITHM LIST IN DISCOVERY IS READ FROM THE CODE THAT ENFORCES IT.
 *
 * Three lists in this document were hardcoded copies of a constant living somewhere else:
 * the id_token alg (derived from the keystore while issuance pinned RS256 — a real bug,
 * and one that self-healed so it left no evidence), the DPoP algs, and the client-assertion
 * algs. Each was correct on the day it was written; each was one edit from advertising an
 * algorithm the validator refuses, which breaks a conformant client that pins what it was
 * told.
 *
 * This asserts the three now agree with their authorities. It cannot stop a fourth list
 * being added by hand, but it does mean the three that were wrong stay right.
 */
it('advertises only algorithms the code enforcing them accepts', function (): void {
    $doc = $this->getJson('/.well-known/openid-configuration')->assertOk()->json();

    expect($doc['id_token_signing_alg_values_supported'])
        ->toBe([TokenController::ID_TOKEN_ALG->value])
        ->and($doc['dpop_signing_alg_values_supported'])
        ->toBe(DpopProofValidator::ALLOWED_ALGS)
        ->and($doc['token_endpoint_auth_signing_alg_values_supported'])
        ->toBe(ClientAssertionValidator::ALLOWED_ALGS);
});

/**
 * EVERY ADVERTISED SCOPE MUST BE OBTAINABLE BY SOMETHING.
 *
 * `scopes_supported` is a promise. `groups` sat in it while being absent from the
 * dynamic-registration allow-list and from the console's picker, so no client could ever
 * be granted it — `kubectl oidc-login` reads the document, asks for `openid groups`, and
 * is refused by the server that advertised it. `organizations` had the identical defect
 * one release earlier and the fix was recorded in a comment; `groups` was added
 * afterwards and missed both lists again.
 *
 * Checked against the DCR allow-list, which is the path a client can walk unattended. A
 * scope reachable only by an operator typing it into a box is not discoverable, and this
 * document says it is.
 */
it('advertises no sign-in scope a self-registering client cannot ask for', function (): void {
    $advertised = $this->getJson('/.well-known/openid-configuration')->assertOk()
        ->json('scopes_supported');

    /** @var list<string> $registerable */
    $registerable = config('cbox-id.oauth.dynamic_registration.allowed_scopes', []);

    // Platform-API scopes are deliberately not self-registerable — they grant access to
    // this deployment's own management surface, which is an operator's decision. The
    // sign-in scopes are the ones a relying party discovers and asks for.
    $signIn = array_values(array_filter(
        $advertised,
        static fn (string $scope): bool => ! str_contains($scope, '.'),
    ));

    expect(array_values(array_diff($signIn, $registerable)))->toBe([]);
});
