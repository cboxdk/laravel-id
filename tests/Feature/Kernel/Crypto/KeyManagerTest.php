<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Exceptions\InvalidToken;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('generates an active signing key on first use', function (): void {
    $key = app(KeyManager::class)->activeSigningKey();

    expect($key->status)->toBe(KeyStatus::Active)
        ->and($key->alg)->toBe(SigningAlg::RS256)
        ->and($key->public_key)->toContain('BEGIN PUBLIC KEY')
        ->and(SigningKey::query()->count())->toBe(1);
});

it('reuses the existing active key', function (): void {
    $manager = app(KeyManager::class);

    $first = $manager->activeSigningKey();
    $second = $manager->activeSigningKey();

    expect($second->id)->toBe($first->id)
        ->and(SigningKey::query()->count())->toBe(1);
});

it('rotation demotes the old key to rotating and activates a new one', function (): void {
    $manager = app(KeyManager::class);

    $old = $manager->activeSigningKey();
    $new = $manager->rotate();

    expect($new->id)->not->toBe($old->id)
        ->and($new->status)->toBe(KeyStatus::Active)
        ->and($old->fresh()?->status)->toBe(KeyStatus::Rotating)
        ->and(SigningKey::query()->count())->toBe(2);
});

it('publishes active and rotating keys as a valid JWKS', function (): void {
    $manager = app(KeyManager::class);
    $manager->activeSigningKey();
    $manager->rotate();

    $jwks = $manager->jwks();

    expect($jwks['keys'])->toHaveCount(2)
        ->and($jwks['keys'][0])->toHaveKeys(['kid', 'kty', 'alg', 'use', 'n', 'e'])
        ->and($jwks['keys'][0]['kty'])->toBe('RSA')
        ->and($jwks['keys'][0]['use'])->toBe('sig');
});

it('supports ES256 keys', function (): void {
    $key = app(KeyManager::class)->activeSigningKey(SigningAlg::ES256);
    $jwks = app(KeyManager::class)->jwks();

    expect($key->alg)->toBe(SigningAlg::ES256)
        ->and($jwks['keys'][0])->toHaveKeys(['crv', 'x', 'y'])
        ->and($jwks['keys'][0]['crv'])->toBe('P-256');
});

it('supports EdDSA (Ed25519) keys published as an OKP JWK', function (): void {
    $key = app(KeyManager::class)->activeSigningKey(SigningAlg::EdDSA);
    $jwks = app(KeyManager::class)->jwks();

    expect($key->alg)->toBe(SigningAlg::EdDSA)
        ->and($jwks['keys'][0]['kty'])->toBe('OKP')
        ->and($jwks['keys'][0]['crv'])->toBe('Ed25519')
        ->and($jwks['keys'][0])->toHaveKeys(['kid', 'use', 'alg', 'x'])
        ->and($jwks['keys'][0])->not->toHaveKey('d'); // never publish the private key
});

it('signs and verifies a token with EdDSA end to end', function (): void {
    $keys = app(KeyManager::class);
    $signer = app(TokenSigner::class);

    $keys->activeSigningKey(SigningAlg::EdDSA);
    $token = $signer->sign(['sub' => 'u-ed', 'exp' => time() + 60], SigningAlg::EdDSA);

    expect($signer->verify($token, [SigningAlg::EdDSA])->get('sub'))->toBe('u-ed')
        // An EdDSA token is not accepted when only RSA is allowed (alg is pinned).
        ->and(fn () => $signer->verify($token, [SigningAlg::RS256]))->toThrow(InvalidToken::class);
});

it('retires a key so it leaves the JWKS and no longer verifies tokens', function (): void {
    $keys = app(KeyManager::class);
    $signer = app(TokenSigner::class);

    $active = $keys->activeSigningKey();
    $token = $signer->sign(['sub' => 'u1', 'exp' => time() + 60]);
    // Sanity: it verifies while the key is trusted.
    expect($signer->verify($token, [SigningAlg::RS256])->get('sub'))->toBe('u1');

    $keys->retire($active->kid);

    expect($active->fresh()?->status)->toBe(KeyStatus::Retired)
        ->and($keys->jwks()['keys'])->toBeEmpty();

    // A token signed by the retired key is now rejected.
    expect(fn () => $signer->verify($token, [SigningAlg::RS256]))
        ->toThrow(InvalidToken::class);
});

it('serves JWKS and verification keys from cache and reloads after rotation', function (): void {
    $keys = app(KeyManager::class);
    $keys->activeSigningKey(); // ensure an active key exists

    // Warm both caches, then a second call must touch the database zero times.
    $keys->jwks();
    $keys->verificationKeys();

    DB::enableQueryLog();
    $keys->jwks();
    $keys->verificationKeys();
    $warmQueries = DB::getQueryLog();
    DB::disableQueryLog();

    expect($warmQueries)->toBeEmpty();

    // Rotation invalidates the caches: the new key appears in a freshly-served JWKS.
    $new = $keys->rotate();
    expect(array_column($keys->jwks()['keys'], 'kid'))->toContain($new->kid);
});

// --- transposition guards -------------------------------------------------
//
// Key generation hands back two halves. While that was an `array{0: string, 1: string}`
// both halves were `string`, so swapping them type-checked cleanly and the only
// symptom was the PRIVATE key being published at the JWKS endpoint. The halves are
// now named (GeneratedKeyPair), and these tests fail loudly if they are ever
// re-transposed anyway.

it('stores the public half public and the private half sealed, never the reverse', function (SigningAlg $alg): void {
    $key = app(KeyManager::class)->activeSigningKey($alg);
    $private = app(SecretBox::class)->open($key->private_key_encrypted, $key->secretContext());

    if ($alg === SigningAlg::EdDSA) {
        // Raw sodium: a public key is 32 bytes, a secret key 64 — and the secret key's
        // trailing 32 bytes ARE the public key, so this asserts correspondence too.
        $publicRaw = (string) base64_decode($key->public_key, true);
        $privateRaw = (string) base64_decode($private, true);

        expect(strlen($publicRaw))->toBe(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES)
            ->and(strlen($privateRaw))->toBe(SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)
            ->and(sodium_crypto_sign_publickey_from_secretkey($privateRaw))->toBe($publicRaw);

        return;
    }

    // PEM: the stored public column must be a public key with no private material,
    // and the sealed column must be the private key.
    expect($key->public_key)->toContain('BEGIN PUBLIC KEY')
        ->and($key->public_key)->not->toContain('PRIVATE')
        ->and($private)->toContain('PRIVATE KEY');

    // And they must be the two halves of ONE pair: the public material derived from
    // the sealed private key has to match the material stored in the public column.
    $fromPrivate = openssl_pkey_get_private($private);
    expect($fromPrivate)->not->toBeFalse();
    /** @var array{key: string} $details */
    $details = openssl_pkey_get_details($fromPrivate);

    expect($details['key'])->toBe($key->public_key);
})->with([
    'RS256' => SigningAlg::RS256,
    'ES256' => SigningAlg::ES256,
    'EdDSA' => SigningAlg::EdDSA,
]);

it('publishes only public material in the JWKS', function (SigningAlg $alg): void {
    $key = app(KeyManager::class)->activeSigningKey($alg);
    $private = app(SecretBox::class)->open($key->private_key_encrypted, $key->secretContext());

    $jwks = app(KeyManager::class)->jwks();
    $jwk = $jwks['keys'][0];

    // No private exponent / seed under any of the names a private JWK would use,
    // and no PEM private block smuggled into a value.
    expect($jwk)->not->toHaveKey('d')
        ->and($jwk)->not->toHaveKey('p')
        ->and($jwk)->not->toHaveKey('q')
        ->and(json_encode($jwks))->not->toContain('PRIVATE');

    if ($alg === SigningAlg::EdDSA) {
        // x is the 32-byte public key, not the 64-byte secret key.
        $x = Base64Url::decode($jwk['x']);
        expect(strlen($x))->toBe(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES)
            ->and($x)->toBe((string) base64_decode($key->public_key, true));

        return;
    }

    // The published curve point / modulus must be the one belonging to the sealed
    // private key — i.e. the JWKS describes the PUBLIC half of the same pair.
    $fromPrivate = openssl_pkey_get_private($private);
    expect($fromPrivate)->not->toBeFalse();
    $details = openssl_pkey_get_details($fromPrivate);

    if ($alg === SigningAlg::RS256) {
        expect($jwk['n'])->toBe(Base64Url::encode($details['rsa']['n']))
            ->and($jwk['e'])->toBe(Base64Url::encode($details['rsa']['e']));

        return;
    }

    expect($jwk['x'])->toBe(Base64Url::encode($details['ec']['x']))
        ->and($jwk['y'])->toBe(Base64Url::encode($details['ec']['y']));
})->with([
    'RS256' => SigningAlg::RS256,
    'ES256' => SigningAlg::ES256,
    'EdDSA' => SigningAlg::EdDSA,
]);

it('returns the current active key from a persistent manager instance after rotation', function (): void {
    // Guards the regression where a process-lifetime memo kept serving a retired key
    // in a long-lived worker. The SAME instance must reflect the rotation.
    $keys = app(KeyManager::class);
    $first = $keys->activeSigningKey();
    $keys->rotate();
    $second = $keys->activeSigningKey();

    expect($second->kid)->not->toBe($first->kid)
        ->and($second->status)->toBe(KeyStatus::Active)
        ->and($first->fresh()?->status)->toBe(KeyStatus::Rotating);
});
