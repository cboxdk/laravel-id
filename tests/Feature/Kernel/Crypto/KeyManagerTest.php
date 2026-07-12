<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Exceptions\InvalidToken;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Illuminate\Foundation\Testing\RefreshDatabase;

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
