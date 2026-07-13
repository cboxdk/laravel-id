<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Dpop\DpopProofValidator;
use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function base64url(string $binary): string
{
    return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
}

/**
 * A fresh P-256 keypair plus its public JWK, as a DPoP client would hold.
 *
 * @return array{pem: string, jwk: array<string, string>}
 */
function dpopKey(): array
{
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    openssl_pkey_export($key, $pem);
    $d = openssl_pkey_get_details($key);

    return [
        'pem' => (string) $pem,
        'jwk' => [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => base64url($d['ec']['x']),
            'y' => base64url($d['ec']['y']),
        ],
    ];
}

/**
 * Build a signed DPoP proof for a method+URL.
 *
 * @param  array{pem: string, jwk: array<string, string>}  $key
 * @param  array<string, mixed>  $overrides
 */
function dpopProof(array $key, string $htm, string $htu, array $overrides = []): string
{
    $claims = array_merge([
        'htm' => $htm,
        'htu' => $htu,
        'iat' => time(),
        'jti' => bin2hex(random_bytes(12)),
    ], $overrides);

    return JWT::encode($claims, $key['pem'], 'ES256', null, ['typ' => 'dpop+jwt', 'jwk' => $key['jwk']]);
}

it('returns the RFC 7638 thumbprint for a valid proof', function (): void {
    $key = dpopKey();
    $proof = dpopProof($key, 'POST', 'https://id.test/oauth/token');

    $jkt = app(DpopProofValidator::class)->verify($proof, 'POST', 'https://id.test/oauth/token');

    // The thumbprint is the canonical-JWK SHA-256, base64url — 43 chars, no padding.
    expect($jkt)->toBeString()->toHaveLength(43)
        ->and($jkt)->toBe(base64url(hash('sha256', json_encode([
            'crv' => $key['jwk']['crv'], 'kty' => 'EC', 'x' => $key['jwk']['x'], 'y' => $key['jwk']['y'],
        ], JSON_UNESCAPED_SLASHES), true)));
});

it('rejects a replayed proof (same jti twice)', function (): void {
    $key = dpopKey();
    $proof = dpopProof($key, 'POST', 'https://id.test/oauth/token');
    $validator = app(DpopProofValidator::class);

    $validator->verify($proof, 'POST', 'https://id.test/oauth/token');

    expect(fn () => $validator->verify($proof, 'POST', 'https://id.test/oauth/token'))
        ->toThrow(InvalidDpopProof::class);
});

it('rejects a proof bound to a different method or URL', function (): void {
    $key = dpopKey();
    $validator = app(DpopProofValidator::class);

    expect(fn () => $validator->verify(dpopProof($key, 'POST', 'https://id.test/oauth/token'), 'GET', 'https://id.test/oauth/token'))
        ->toThrow(InvalidDpopProof::class)
        ->and(fn () => $validator->verify(dpopProof($key, 'POST', 'https://id.test/oauth/token'), 'POST', 'https://evil.test/oauth/token'))
        ->toThrow(InvalidDpopProof::class);
});

it('rejects a stale proof and one signed by a mismatched key', function (): void {
    $key = dpopKey();
    $validator = app(DpopProofValidator::class);

    // Stale iat.
    expect(fn () => $validator->verify(
        dpopProof($key, 'POST', 'https://id.test/oauth/token', ['iat' => time() - 600]),
        'POST', 'https://id.test/oauth/token'
    ))->toThrow(InvalidDpopProof::class);

    // Header jwk swapped for a different key than the one that signed — signature fails.
    $other = dpopKey();
    $forged = JWT::encode(
        ['htm' => 'POST', 'htu' => 'https://id.test/oauth/token', 'iat' => time(), 'jti' => 'x'],
        $key['pem'], 'ES256', null, ['typ' => 'dpop+jwt', 'jwk' => $other['jwk']],
    );
    expect(fn () => $validator->verify($forged, 'POST', 'https://id.test/oauth/token'))
        ->toThrow(InvalidDpopProof::class);
});

it('sender-constrains an access token issued at the token endpoint', function (): void {
    $registered = $this->makeClient(['api.read']);
    $key = dpopKey();
    $url = 'http://localhost/oauth/token';

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ], ['DPoP' => dpopProof($key, 'POST', $url)]);

    $response->assertOk()->assertJsonPath('token_type', 'DPoP');

    // The access token carries cnf.jkt equal to the proof key's thumbprint.
    $payload = json_decode((string) JWT::urlsafeB64Decode(explode('.', (string) $response->json('access_token'))[1]), true);
    $expectedJkt = base64url(hash('sha256', json_encode([
        'crv' => $key['jwk']['crv'], 'kty' => 'EC', 'x' => $key['jwk']['x'], 'y' => $key['jwk']['y'],
    ], JSON_UNESCAPED_SLASHES), true));

    expect($payload['cnf']['jkt'])->toBe($expectedJkt);
});

it('rejects a bad DPoP proof at the token endpoint', function (): void {
    $registered = $this->makeClient(['api.read']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ], ['DPoP' => 'not-a-valid-proof'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_dpop_proof');
});

it('advertises DPoP signing algs in the authorization-server metadata', function (): void {
    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('dpop_signing_alg_values_supported', ['ES256', 'RS256', 'EdDSA']);
});
