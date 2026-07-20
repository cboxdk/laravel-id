<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\ClientAssertion\ClientAssertionValidator;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

// A fixed issuer so the assertion audience is predictable across the suite.
beforeEach(function (): void {
    config(['cbox-id.issuer' => 'https://id.test']);
});

if (! function_exists('pkjBase64Url')) {
    function pkjBase64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}

if (! function_exists('pkjRsaKey')) {
    /**
     * A fresh RSA-2048 keypair plus its public JWK, as a `private_key_jwt` client holds.
     *
     * @return array{pem: string, jwk: array<string, string>, kid: string}
     */
    function pkjRsaKey(string $kid = 'test-key-1'): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
        openssl_pkey_export($key, $pem);
        $d = openssl_pkey_get_details($key);

        return [
            'pem' => (string) $pem,
            'kid' => $kid,
            'jwk' => [
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'kid' => $kid,
                'n' => pkjBase64Url($d['rsa']['n']),
                'e' => pkjBase64Url($d['rsa']['e']),
            ],
        ];
    }
}

if (! function_exists('pkjEcKey')) {
    /**
     * A fresh P-256 keypair plus its public JWK (for the ES256 assertion branch).
     *
     * @return array{pem: string, jwk: array<string, string>, kid: string}
     */
    function pkjEcKey(string $kid = 'test-ec-1'): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        openssl_pkey_export($key, $pem);
        $d = openssl_pkey_get_details($key);

        return [
            'pem' => (string) $pem,
            'kid' => $kid,
            'jwk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'alg' => 'ES256',
                'use' => 'sig',
                'kid' => $kid,
                'x' => pkjBase64Url(str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT)),
                'y' => pkjBase64Url(str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT)),
            ],
        ];
    }
}

if (! function_exists('pkjRegister')) {
    /**
     * Register a confidential client whose only credential is the given public JWK.
     *
     * @param  array{pem: string, jwk: array<string, string>, kid: string}  $key
     */
    function pkjRegister(array $key): RegisteredClient
    {
        return app(ClientRegistry::class)->register(new NewClient(
            'private_key_jwt client',
            ClientType::Confidential,
            scopes: ['api.read'],
            jwks: ['keys' => [$key['jwk']]],
        ));
    }
}

if (! function_exists('pkjAssertion')) {
    /**
     * Sign a client-authentication assertion (RFC 7523 §3) with the client's key.
     *
     * @param  array{pem: string, jwk: array<string, string>, kid: string}  $key
     * @param  array<string, mixed>  $overrides
     */
    function pkjAssertion(string $clientId, array $key, string $alg = 'RS256', array $overrides = []): string
    {
        $claims = array_merge([
            'iss' => $clientId,
            'sub' => $clientId,
            'aud' => 'https://id.test/oauth/token',
            'jti' => bin2hex(random_bytes(16)),
            'iat' => time(),
            'exp' => time() + 60,
        ], $overrides);

        return JWT::encode($claims, $key['pem'], $alg, $key['kid']);
    }
}

it('authenticates client_credentials with a private_key_jwt assertion (RFC 7523, RS256)', function (): void {
    $key = pkjRsaKey();
    $registered = pkjRegister($key);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => ASSERTION_TYPE,
        'client_assertion' => pkjAssertion($registered->client->client_id, $key),
        'scope' => 'api.read',
    ]);

    $response->assertOk()
        ->assertJsonPath('token_type', 'Bearer')
        ->assertJsonStructure(['access_token', 'expires_in']);
});

it('authenticates with an ES256 assertion (real EC vector)', function (): void {
    $key = pkjEcKey();
    $registered = pkjRegister($key);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => ASSERTION_TYPE,
        'client_assertion' => pkjAssertion($registered->client->client_id, $key, 'ES256'),
        'scope' => 'api.read',
    ])->assertOk()->assertJsonStructure(['access_token']);
});

it('rejects an assertion signed by a key the client did not register', function (): void {
    $registered = pkjRegister(pkjRsaKey());
    $attacker = pkjRsaKey('attacker-key');

    // Same kid as the registered key, but a different private key underneath.
    $attacker['kid'] = 'test-key-1';

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => ASSERTION_TYPE,
        'client_assertion' => pkjAssertion($registered->client->client_id, $attacker),
        'scope' => 'api.read',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('rejects an expired assertion', function (): void {
    $key = pkjRsaKey();
    $registered = pkjRegister($key);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => ASSERTION_TYPE,
        'client_assertion' => pkjAssertion($registered->client->client_id, $key, 'RS256', [
            'iat' => time() - 600,
            'exp' => time() - 300,
        ]),
        'scope' => 'api.read',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('rejects an assertion with no exp (RFC 7523 §3 requires it — closes the ~1s replay window)', function (): void {
    $key = pkjRsaKey();
    $registered = pkjRegister($key);

    // exp => null makes the claim effectively absent; firebase would not enforce a
    // lifetime, and the jti replay-guard would lapse in ~1s.
    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => ASSERTION_TYPE,
        'client_assertion' => pkjAssertion($registered->client->client_id, $key, 'RS256', ['exp' => null]),
        'scope' => 'api.read',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('rejects an assertion whose lifetime exceeds the cap (jti must stay memorable)', function (): void {
    $key = pkjRsaKey();
    $registered = pkjRegister($key);

    // iat now, exp 400s out → 400s lifetime > 300s cap.
    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => ASSERTION_TYPE,
        'client_assertion' => pkjAssertion($registered->client->client_id, $key, 'RS256', [
            'iat' => time(),
            'exp' => time() + 400,
        ]),
        'scope' => 'api.read',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('rejects an assertion whose audience is not this authorization server', function (): void {
    $key = pkjRsaKey();
    $registered = pkjRegister($key);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => ASSERTION_TYPE,
        'client_assertion' => pkjAssertion($registered->client->client_id, $key, 'RS256', [
            'aud' => 'https://evil.example/oauth/token',
        ]),
        'scope' => 'api.read',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('rejects an assertion where iss does not equal sub', function (): void {
    $key = pkjRsaKey();
    $registered = pkjRegister($key);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => ASSERTION_TYPE,
        'client_assertion' => pkjAssertion($registered->client->client_id, $key, 'RS256', [
            'iss' => 'someone-else',
        ]),
        'scope' => 'api.read',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('rejects a replayed jti (single-use assertion)', function (): void {
    $key = pkjRsaKey();
    $registered = pkjRegister($key);
    $assertion = pkjAssertion($registered->client->client_id, $key);

    $payload = [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => ASSERTION_TYPE,
        'client_assertion' => $assertion,
        'scope' => 'api.read',
    ];

    $this->postJson('/oauth/token', $payload)->assertOk();
    // Same assertion (same jti) a second time is a replay.
    $this->postJson('/oauth/token', $payload)->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('rejects a symmetric alg (no HS256 / alg-confusion)', function (): void {
    $key = pkjRsaKey();
    $registered = pkjRegister($key);

    // Forge an HS256 assertion using the (public) modulus as the MAC key — the
    // classic RSA→HMAC confusion. The allow-list refuses HS256 outright.
    $forged = JWT::encode([
        'iss' => $registered->client->client_id,
        'sub' => $registered->client->client_id,
        'aud' => 'https://id.test/oauth/token',
        'jti' => bin2hex(random_bytes(16)),
        'iat' => time(),
        'exp' => time() + 60,
    ], $key['jwk']['n'], 'HS256', $key['kid']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => ASSERTION_TYPE,
        'client_assertion' => $forged,
        'scope' => 'api.read',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('refuses to combine a private_key_jwt assertion with a client secret (RFC 6749 §2.3)', function (): void {
    $key = pkjRsaKey();
    $registered = pkjRegister($key);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => ASSERTION_TYPE,
        'client_assertion' => pkjAssertion($registered->client->client_id, $key),
        'client_secret' => 'csec_whatever',
        'scope' => 'api.read',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('advertises private_key_jwt in discovery metadata', function (): void {
    $this->get('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('token_endpoint_auth_methods_supported', fn (array $m): bool => in_array('private_key_jwt', $m, true))
        ->assertJsonPath('token_endpoint_auth_signing_alg_values_supported', ['RS256', 'ES256', 'EdDSA']);
});

it('verifies an assertion directly through the validator contract', function (): void {
    $key = pkjRsaKey();
    $registered = pkjRegister($key);

    $client = app(ClientAssertionValidator::class)
        ->verify(pkjAssertion($registered->client->client_id, $key));

    expect($client)->not->toBeNull()
        ->and($client->client_id)->toBe($registered->client->client_id);
});
