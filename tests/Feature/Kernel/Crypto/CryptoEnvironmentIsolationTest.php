<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Exceptions\InvalidToken;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * @group isolation
 *
 * Crypto isolation: each environment has its own signing keys, so a token minted
 * in one environment must never verify in another. This is what stops a staging
 * token from being accepted in production.
 */
it('never verifies a token across environments', function (): void {
    $signer = app(TokenSigner::class);

    $token = $this->runAsEnvironment('env_a', fn () => $signer->sign(['sub' => 'user-1']));

    // Same environment → verifies.
    $this->runAsEnvironment('env_a', function () use ($signer, $token): void {
        expect($signer->verify($token, [SigningAlg::RS256])->subject())->toBe('user-1');
    });

    // Different environment → its JWKS lacks the kid, so verification fails hard.
    $this->runAsEnvironment('env_b', function () use ($signer, $token): void {
        expect(fn () => $signer->verify($token, [SigningAlg::RS256]))->toThrow(InvalidToken::class);
    });
});

it('exposes a distinct JWKS per environment', function (): void {
    $keys = app(KeyManager::class);

    $kidA = $this->runAsEnvironment('env_a', fn () => $keys->activeSigningKey()->kid);
    $kidB = $this->runAsEnvironment('env_b', fn () => $keys->activeSigningKey()->kid);

    expect($kidA)->not->toBe($kidB);

    $jwksB = $this->runAsEnvironment('env_b', fn () => collect($keys->jwks()['keys'])->pluck('kid')->all());
    expect($jwksB)->toContain($kidB)->not->toContain($kidA);
});
