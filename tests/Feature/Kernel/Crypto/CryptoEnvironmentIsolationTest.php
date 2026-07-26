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

it('caches the JWKS under each job\'s OWN environment across a worker reset', function (): void {
    // KeyManager is a `singleton` and EnvironmentContext is `scoped`. A queue worker's
    // forgetScopedInstances() unsets the binding but does not reset the object, so a
    // CAPTURED context would keep the first job's environment for the life of the
    // process — and that value is the CACHE KEY for the JWKS and the verification keys.
    //
    // The class already refuses to memoize the active signing key to avoid exactly this
    // family of staleness; capturing the context defeated that care one level up.
    //
    // Both keys are minted UP FRONT on purpose. generate() calls flushCaches(), so
    // minting inside the second "job" would clear the mis-keyed entry and hide the very
    // bug under test — the assertion would then pass with or without the fix.
    $keys = app(KeyManager::class);
    $kidA = $this->runAsEnvironment('env_a', fn () => $keys->activeSigningKey()->kid);
    $kidB = $this->runAsEnvironment('env_b', fn () => $keys->activeSigningKey()->kid);
    expect($kidA)->not->toBe($kidB);

    // Job A warms the JWKS cache under its own environment.
    $this->actingAsEnvironment('env_a');
    expect(collect($keys->jwks()['keys'])->pluck('kid')->all())->toContain($kidA);

    // The between-jobs container reset a queue worker performs.
    $this->app->forgetScopedInstances();

    // Job B, same worker, same captured singleton. With a captured context the cache key
    // is still env_a's, so this READ HITS env_a's warm entry and hands job B the wrong
    // environment's published keys.
    $this->actingAsEnvironment('env_b');
    expect(app(KeyManager::class))->toBe($keys); // the singleton really is reused

    $kidsB = collect($keys->jwks()['keys'])->pluck('kid')->all();

    expect($kidsB)->toContain($kidB)->not->toContain($kidA);
});
