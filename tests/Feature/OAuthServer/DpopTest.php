<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Dpop\DpopProofValidator;
use Cbox\Id\OAuthServer\Enums\ClientType;
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

    // RFC 7518 §6.2.1.2: for P-256 the x/y coordinates are the fixed 32-byte
    // field elements, left-padded with zeros. OpenSSL strips leading zero bytes,
    // so ~0.75% of keys return a short (31-byte) coordinate — encoding that
    // unpadded yields a malformed JWK whose reconstructed key fails signature
    // verification, making any DPoP test intermittently 400 in the full suite.
    return [
        'pem' => (string) $pem,
        'jwk' => [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => base64url(str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => base64url(str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT)),
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

it('accepts a proof whose EC coordinate lost a leading zero byte (RFC 7518 padding)', function (): void {
    // The ~0.75% case: an OpenSSL client emits x/y with the leading zero byte
    // stripped, so the JWK carries a short (31-byte) coordinate. Find such a key.
    $pem = null;
    $d = null;
    for ($i = 0; $i < 5000; $i++) {
        $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        openssl_pkey_export($k, $pem);
        $d = openssl_pkey_get_details($k);
        if (strlen($d['ec']['x']) < 32 || strlen($d['ec']['y']) < 32) {
            break;
        }
        $pem = null;
    }
    expect($pem)->not->toBeNull('no short-coordinate P-256 key generated in 5000 tries');

    $unpadded = ['kty' => 'EC', 'crv' => 'P-256', 'x' => base64url($d['ec']['x']), 'y' => base64url($d['ec']['y'])];
    $proof = JWT::encode(
        ['htm' => 'POST', 'htu' => 'https://id.test/oauth/token', 'iat' => time(), 'jti' => bin2hex(random_bytes(12))],
        (string) $pem, 'ES256', null, ['typ' => 'dpop+jwt', 'jwk' => $unpadded],
    );

    $jkt = app(DpopProofValidator::class)->verify($proof, 'POST', 'https://id.test/oauth/token');

    // Verified despite the short coordinate, and the jkt matches the padded
    // canonical form — the value a compliant client and the token endpoint use.
    $expected = base64url(hash('sha256', json_encode([
        'crv' => 'P-256', 'kty' => 'EC',
        'x' => base64url(str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT)),
        'y' => base64url(str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT)),
    ], JSON_UNESCAPED_SLASHES), true));

    expect($jkt)->toBe($expected);
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
    $registered = $this->makeClient(['api.read'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);
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
    $registered = $this->makeClient(['api.read'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ], ['DPoP' => 'not-a-valid-proof'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_dpop_proof');
});

/**
 * Mint a DPoP-bound, openid-scoped access token via the token endpoint.
 *
 * @param  object{client: object{client_id: string}, secret: string}  $registered
 * @param  array{pem: string, jwk: array<string, string>}  $key
 */
function mintBoundToken(object $test, object $registered, array $key): string
{
    return (string) $test->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
    ], ['DPoP' => dpopProof($key, 'POST', 'http://localhost/oauth/token')])
        ->assertOk()->json('access_token');
}

it('rejects a sender-constrained token presented as a plain bearer at the resource', function (): void {
    $key = dpopKey();
    $token = mintBoundToken($this, $this->makeClient(['openid'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']), $key);

    // A stolen bound token, replayed as a bearer with no proof of possession.
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$token])
        ->assertStatus(401);
});

it('accepts a sender-constrained token with a matching DPoP proof at the resource', function (): void {
    $key = dpopKey();
    $token = mintBoundToken($this, $this->makeClient(['openid'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']), $key);
    $url = 'http://localhost/oauth/userinfo';

    $proof = dpopProof($key, 'GET', $url, ['ath' => base64url(hash('sha256', $token, true))]);

    $this->getJson('/oauth/userinfo', ['Authorization' => 'DPoP '.$token, 'DPoP' => $proof])
        ->assertOk()->assertJsonStructure(['sub']);
});

it('rejects a resource proof that omits the ath token binding', function (): void {
    $key = dpopKey();
    $token = mintBoundToken($this, $this->makeClient(['openid'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']), $key);
    $url = 'http://localhost/oauth/userinfo';

    // Correct key + request, but no ath — a proof captured for a different call
    // must not authorize this token (RFC 9449 §4.3).
    $proof = dpopProof($key, 'GET', $url);

    $this->getJson('/oauth/userinfo', ['Authorization' => 'DPoP '.$token, 'DPoP' => $proof])
        ->assertStatus(401);
});

it('rejects a resource proof signed by a key other than the token binding', function (): void {
    $key = dpopKey();
    $attacker = dpopKey();
    $token = mintBoundToken($this, $this->makeClient(['openid'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']), $key);
    $url = 'http://localhost/oauth/userinfo';

    // Attacker holds the stolen token and forges a fresh proof with THEIR key —
    // the thumbprint won't match cnf.jkt.
    $proof = dpopProof($attacker, 'GET', $url, ['ath' => base64url(hash('sha256', $token, true))]);

    $this->getJson('/oauth/userinfo', ['Authorization' => 'DPoP '.$token, 'DPoP' => $proof])
        ->assertStatus(401);
});

it('still serves a plain (unbound) bearer token at the resource', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']);
    $token = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
    ])->assertOk()->json('access_token');

    // No cnf.jkt → ordinary Bearer access is unaffected.
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$token])
        ->assertOk()->assertJsonStructure(['sub']);
});

/**
 * Mint a DPoP-bound refresh token for a public client via the authorization_code
 * grant (offline_access), returning the raw refresh token.
 *
 * @param  array{pem: string, jwk: array<string, string>}  $key
 */
function boundRefreshToken(object $test, string $clientId, array $key): string
{
    $verifier = 'a-sufficiently-long-code-verifier-1234567890';
    $code = app(AuthorizationCodes::class)->issue(
        $clientId, 'user_42', 'org_a', 'https://app.test/cb',
        ['openid', 'offline_access'],
        Base64Url::encode(hash('sha256', $verifier, true)), 'S256', null, 1_700_000_000, ['pwd'],
    );

    return (string) $test->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
    ], ['DPoP' => dpopProof($key, 'POST', 'http://localhost/oauth/token')])
        ->assertOk()->json('refresh_token');
}

it('binds a refresh token to the DPoP key and rotates it only with a matching proof', function (): void {
    $key = dpopKey();
    $clientId = $this->makeClient(['openid', 'offline_access'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'])->client->client_id;
    $refresh = boundRefreshToken($this, $clientId, $key);
    $tokenUrl = 'http://localhost/oauth/token';

    // Rotating with a proof of the SAME key succeeds and returns a fresh token.
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $clientId,
        'refresh_token' => $refresh,
    ], ['DPoP' => dpopProof($key, 'POST', $tokenUrl)])
        ->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
});

it('refuses to rotate a DPoP-bound refresh token without a proof', function (): void {
    $key = dpopKey();
    $clientId = $this->makeClient(['openid', 'offline_access'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'])->client->client_id;
    $refresh = boundRefreshToken($this, $clientId, $key);

    // A stolen bound token, replayed with no DPoP header at all.
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $clientId,
        'refresh_token' => $refresh,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('refuses to rotate a DPoP-bound refresh token with a different key', function (): void {
    $key = dpopKey();
    $attacker = dpopKey();
    $clientId = $this->makeClient(['openid', 'offline_access'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'])->client->client_id;
    $refresh = boundRefreshToken($this, $clientId, $key);

    // Attacker holds the stolen token but can only prove their OWN key.
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $clientId,
        'refresh_token' => $refresh,
    ], ['DPoP' => dpopProof($attacker, 'POST', 'http://localhost/oauth/token')])
        ->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('advertises DPoP signing algs in the authorization-server metadata', function (): void {
    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('dpop_signing_alg_values_supported', ['ES256', 'RS256', 'EdDSA']);
});
