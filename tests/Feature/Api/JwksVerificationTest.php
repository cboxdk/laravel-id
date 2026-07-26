<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Everything else in the suite verifies a token through `TokenSigner::verify()`,
 * which loads the PRIVATE key from the database and derives the public half from
 * it. That path is green even if the JWKS endpoint publishes the wrong key's
 * modulus, an unmatched `kid`, or a stale key — and a relying party has nothing
 * BUT those published bytes. These tests throw the server-side key material away
 * and rebuild the key from the HTTP response alone, exactly as an RP does.
 */

/**
 * Fetch the served JWKS and turn it into firebase key objects — no server-side
 * key material involved.
 *
 * @return array<string, Key>
 */
function keysFromPublishedJwks(): array
{
    /** @var array<string, mixed> $jwks */
    $jwks = test()->getJson('/.well-known/jwks.json')->assertOk()->json();

    return JWK::parseKeySet($jwks);
}

/** Mint an id_token through the real authorization-code exchange. */
function issueIdTokenViaCodeExchange(): string
{
    $clientId = test()->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code'])->client->client_id;

    $verifier = 'a-sufficiently-long-code-verifier-1234567890';
    $code = app(AuthorizationCodes::class)->issue(
        $clientId,
        'user_42',
        'org_a',
        'https://app.test/cb',
        ['openid'],
        Base64Url::encode(hash('sha256', $verifier, true)),
        'S256',
    );

    return (string) test()->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
    ])->assertOk()->json('id_token');
}

it('verifies an issued id_token using ONLY the bytes served at the JWKS endpoint', function (): void {
    $idToken = issueIdTokenViaCodeExchange();

    $decoded = JWT::decode($idToken, keysFromPublishedJwks());

    expect($decoded->sub)->toBe('user_42');
});

it('serves a kid that matches the one in the issued token header', function (): void {
    $idToken = issueIdTokenViaCodeExchange();

    /** @var array{kid?: string} $header */
    $header = json_decode(Base64Url::decode(explode('.', $idToken)[0]), true, 512, JSON_THROW_ON_ERROR);

    /** @var array{keys: list<array<string, mixed>>} $jwks */
    $jwks = $this->getJson('/.well-known/jwks.json')->assertOk()->json();

    // Without this an RP that selects by kid (the normal behaviour) finds no key at
    // all, even though every published modulus is correct.
    expect($header['kid'] ?? null)->toBeString()
        ->and(array_column($jwks['keys'], 'kid'))->toContain($header['kid']);
});

it('does not verify against a JWKS whose modulus has been altered by one character', function (): void {
    // Proves the published `n` is genuinely load-bearing — that the test above is
    // not passing for some incidental reason.
    $idToken = issueIdTokenViaCodeExchange();

    /** @var array{keys: list<array<string, mixed>>} $jwks */
    $jwks = $this->getJson('/.well-known/jwks.json')->assertOk()->json();

    $n = (string) $jwks['keys'][0]['n'];
    $jwks['keys'][0]['n'] = substr($n, 0, 20).($n[20] === 'A' ? 'B' : 'A').substr($n, 21);

    $failed = false;
    try {
        JWT::decode($idToken, JWK::parseKeySet($jwks));
    } catch (Throwable) {
        $failed = true;
    }

    expect($failed)->toBeTrue();
});

it('never publishes private key material in the JWKS', function (): void {
    app(KeyManager::class)->activeSigningKey();

    /** @var array{keys: list<array<string, mixed>>} $jwks */
    $jwks = $this->getJson('/.well-known/jwks.json')->assertOk()->json();

    foreach ($jwks['keys'] as $key) {
        // `d` is the RSA private exponent / EC private scalar / OKP private key.
        expect($key)->not->toHaveKey('d')
            ->and($key)->not->toHaveKey('p')
            ->and($key)->not->toHaveKey('q');
    }
});

it('publishes an ES256 key an RP can verify with, from the served crv/x/y alone', function (): void {
    app(KeyManager::class)->activeSigningKey(SigningAlg::ES256);
    $token = app(TokenSigner::class)->sign(['sub' => 'u-ec', 'exp' => time() + 60], SigningAlg::ES256);

    // An x or y published with a stripped leading zero byte (RFC 7518 §6.2.1.2) or a
    // swapped coordinate rebuilds the wrong point and fails here.
    expect(JWT::decode($token, keysFromPublishedJwks())->sub)->toBe('u-ec');
});

it('publishes an EdDSA (OKP) key an RP can verify with, from the served x alone', function (): void {
    app(KeyManager::class)->activeSigningKey(SigningAlg::EdDSA);
    $token = app(TokenSigner::class)->sign(['sub' => 'u-ed', 'exp' => time() + 60], SigningAlg::EdDSA);

    expect(JWT::decode($token, keysFromPublishedJwks())->sub)->toBe('u-ed');
});

it('serves the rotated key so an RP can verify tokens signed on either side of a rotation', function (): void {
    $keys = app(KeyManager::class);
    $signer = app(TokenSigner::class);

    $keys->activeSigningKey();
    $beforeRotation = $signer->sign(['sub' => 'u-old', 'exp' => time() + 60]);

    $keys->rotate();
    $afterRotation = $signer->sign(['sub' => 'u-new', 'exp' => time() + 60]);

    // One freshly-fetched JWKS must satisfy both — the rotating key stays published
    // for the overlap window, and the new key appears immediately.
    $published = keysFromPublishedJwks();

    expect(JWT::decode($beforeRotation, $published)->sub)->toBe('u-old')
        ->and(JWT::decode($afterRotation, $published)->sub)->toBe('u-new');
});

it('stops verifying with the published JWKS once the key is retired', function (): void {
    $keys = app(KeyManager::class);
    $active = $keys->activeSigningKey();
    $token = app(TokenSigner::class)->sign(['sub' => 'u1', 'exp' => time() + 60]);

    expect(JWT::decode($token, keysFromPublishedJwks())->sub)->toBe('u1');

    $keys->retire($active->kid);

    // The retired key is gone from the served set, so an RP holding only the
    // published bytes can no longer validate the token it once accepted.
    /** @var array<string, mixed> $jwks */
    $jwks = $this->getJson('/.well-known/jwks.json')->assertOk()->json();
    expect($jwks['keys'])->toBeEmpty();
});
