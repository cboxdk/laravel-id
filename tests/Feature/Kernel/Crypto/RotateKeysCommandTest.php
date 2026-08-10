<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * ROTATION RUNS FROM CRON, WHICH HAS NO ENVIRONMENT — and that is the case that was broken.
 *
 * `SigningKey` is environment-owned and the scope is deny-by-default, so every query in
 * this command compiled to `1 = 0` when no context was set. Measured before the fix, from
 * a context-less run against a seeded environment: the command threw a NOT NULL violation,
 * generated no key, and left the original key Active — while `--retire-after` reported
 * "Retired 0 rotating key(s)", which reads as "there were none".
 *
 * Every assertion below is made from OUTSIDE any environment context, because that is
 * where the scheduler stands.
 */
function seedKeyIn(string $environmentId): string
{
    return app(EnvironmentContext::class)->runAs(
        GenericEnvironment::of($environmentId),
        fn (): string => app(KeyManager::class)->activeSigningKey()->kid,
    );
}

it('rotates every environment when the scheduler runs it with no context', function (): void {
    $first = seedKeyIn('env_one');
    $second = seedKeyIn('env_two');

    app(EnvironmentContext::class)->set(null);

    $this->artisan('cbox-id:keys:rotate')->assertSuccessful();

    $context = app(EnvironmentContext::class);

    // The keys that were active are no longer active — in BOTH environments, which is the
    // half a single-environment fix would still get wrong.
    foreach ([$first, $second] as $kid) {
        $status = $context->withoutScope(
            fn () => SigningKey::query()->where('kid', $kid)->value('status'),
        );

        expect($status)->not->toBe(KeyStatus::Active);
    }

    // …and each environment has a new active key, rather than one environment having two.
    foreach (['env_one', 'env_two'] as $environmentId) {
        $active = $context->withoutScope(
            fn (): int => SigningKey::query()
                ->where('environment_id', $environmentId)
                ->where('status', KeyStatus::Active->value)
                ->count(),
        );

        expect($active)->toBe(1);
    }
});

it('says so rather than reporting success when it can see no environments', function (): void {
    app(EnvironmentContext::class)->set(null);

    // "Nothing to rotate" and "I cannot see anything to rotate" are opposite facts that
    // looked identical in the log. An operator responding to a compromise reads this.
    $this->artisan('cbox-id:keys:rotate')
        ->expectsOutputToContain('No environments found')
        ->assertSuccessful();
});

it('rotates only the named environment when one is given', function (): void {
    $first = seedKeyIn('env_one');
    $second = seedKeyIn('env_two');

    app(EnvironmentContext::class)->set(null);

    $this->artisan('cbox-id:keys:rotate', ['--environment' => 'env_one'])->assertSuccessful();

    $context = app(EnvironmentContext::class);

    expect($context->withoutScope(fn () => SigningKey::query()->where('kid', $first)->value('status')))
        ->not->toBe(KeyStatus::Active)
        // Untouched: a targeted rotation must not roll the whole estate.
        ->and($context->withoutScope(fn () => SigningKey::query()->where('kid', $second)->value('status')))
        ->toBe(KeyStatus::Active);
});
