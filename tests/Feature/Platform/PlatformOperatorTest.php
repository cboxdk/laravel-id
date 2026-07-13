<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Platform\Contracts\PlatformOperators;
use Cbox\Id\Platform\Testing\InteractsWithPlatform;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class, InteractsWithTenancy::class, InteractsWithPlatform::class);

it('provisions, finds and authenticates a platform operator', function (): void {
    $ops = app(PlatformOperators::class);

    $op = $this->makeOperator('root@platform.test', 'a-strong-passphrase', 'Root Operator');

    expect($ops->findByEmail('root@platform.test')?->id)->toBe($op->id)
        ->and($ops->find($op->id)?->email)->toBe('root@platform.test')
        ->and($ops->verifyPassword($op->id, 'a-strong-passphrase'))->toBeTrue()
        ->and($ops->verifyPassword($op->id, 'wrong-passphrase'))->toBeFalse();
});

it('hashes the operator password with the configured driver', function (): void {
    $op = app(PlatformOperators::class)->create('h@platform.test', 'secret-passphrase');

    expect($op->password)->not->toBe('secret-passphrase')
        ->and(password_get_info($op->password)['algo'])->not->toBeNull();
});

it('refuses a suspended operator even with the right password', function (): void {
    $ops = app(PlatformOperators::class);
    $op = $ops->create('s@platform.test', 'right-passphrase');

    $op->update(['status' => 'suspended']);

    expect($ops->verifyPassword($op->id, 'right-passphrase'))->toBeFalse();
});

it('reports whether any operator exists yet — the bootstrap gate', function (): void {
    $ops = app(PlatformOperators::class);

    expect($ops->exists())->toBeFalse();

    $ops->create('first@platform.test', 'pw-strong-enough');

    expect($ops->exists())->toBeTrue();
});

/**
 * @group isolation
 *
 * The load-bearing property: an operator stands ABOVE every environment. It is
 * created in one environment's request and resolves, unchanged, from any other —
 * because it is not environment-owned and carries no environment_id at all.
 */
it('is visible from every environment — it stands above the boundary', function (): void {
    $op = $this->runAsEnvironment(
        'env_a',
        fn () => app(PlatformOperators::class)->create('cross@platform.test', 'pw-strong-enough'),
    );

    $fromB = $this->runAsEnvironment(
        'env_b',
        fn () => app(PlatformOperators::class)->findByEmail('cross@platform.test'),
    );

    expect($fromB?->id)->toBe($op->id)
        ->and(Schema::hasColumn('platform_operators', 'environment_id'))->toBeFalse();
});
