<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\Contracts\Accounts;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['cbox-id.environments.base_domains' => ['cboxid.com']]);
});

function resolutionEnvironment(string $slugSeed = 'Acme'): Environment
{
    return app(AccountProvisioner::class)->provision(new AccountBlueprint(
        accountName: $slugSeed,
        ownerEmail: strtolower($slugSeed).'@test.test',
        ownerName: 'Owner',
        ownerPassword: 'supersecret123',
    ))->environment;
}

/**
 * Count the queries a callback issues. This is the measurement the caching claims
 * in this module rest on — not an estimate.
 */
function queriesDuring(Closure $callback): int
{
    $count = 0;
    DB::listen(function () use (&$count): void {
        $count++;
    });

    $callback();

    return $count;
}

it('costs queries on the first resolution and none on the next', function (): void {
    $env = resolutionEnvironment();
    $resolver = app(EnvironmentResolver::class);

    $cold = queriesDuring(fn () => $resolver->resolveForHost('acme.cboxid.com'));
    $warm = queriesDuring(fn () => $resolver->resolveForHost('acme.cboxid.com'));

    // Cold path: the custom-domain lookup misses, the slug lookup hits, then the
    // owning account's liveness is checked — three round trips, on EVERY request,
    // before any endpoint logic ran.
    expect($cold)->toBe(3)
        ->and($warm)->toBe(0)
        ->and($resolver->resolveForHost('acme.cboxid.com')?->environmentKey())->toBe($env->id);
});

it('keeps resolving live when the cache is turned off', function (): void {
    resolutionEnvironment();
    config(['cbox-id.environments.resolution_cache_ttl' => 0]);

    $resolver = app(EnvironmentResolver::class);
    $resolver->resolveForHost('acme.cboxid.com');

    expect(queriesDuring(fn () => $resolver->resolveForHost('acme.cboxid.com')))->toBe(3);
});

it('stops serving a suspended environment on the very next request', function (): void {
    $env = resolutionEnvironment();
    $resolver = app(EnvironmentResolver::class);

    expect($resolver->resolveForHost('acme.cboxid.com'))->not->toBeNull();

    $env->forceFill(['status' => EnvironmentStatus::Suspended])->save();

    expect($resolver->resolveForHost('acme.cboxid.com'))->toBeNull();
});

it('stops and resumes with its account, which the environment row never sees change', function (): void {
    $env = resolutionEnvironment();
    $resolver = app(EnvironmentResolver::class);

    expect($resolver->resolveForHost('acme.cboxid.com'))->not->toBeNull();

    // Suspension is a mass update on `accounts`; no environment model event fires, so
    // this only works because DatabaseAccounts invalidates explicitly.
    app(Accounts::class)->suspend($env->account_id);
    expect($resolver->resolveForHost('acme.cboxid.com'))->toBeNull();

    app(Accounts::class)->reactivate($env->account_id);
    expect($resolver->resolveForHost('acme.cboxid.com'))->not->toBeNull();
});

it('serves a newly attached custom domain immediately, and drops the one it left', function (): void {
    $env = resolutionEnvironment();
    $resolver = app(EnvironmentResolver::class);

    $env->forceFill(['domain' => 'id.acme.test'])->save();
    expect($resolver->resolveForHost('id.acme.test')?->environmentKey())->toBe($env->id);

    $env->forceFill(['domain' => 'auth.acme.test'])->save();

    expect($resolver->resolveForHost('id.acme.test'))->toBeNull()
        ->and($resolver->resolveForHost('auth.acme.test')?->environmentKey())->toBe($env->id);
});

it('never answers one host with another host\'s environment', function (): void {
    $first = resolutionEnvironment('Acme');
    $second = resolutionEnvironment('Globex');

    $resolver = app(EnvironmentResolver::class);

    expect($resolver->resolveForHost('acme.cboxid.com')?->environmentKey())->toBe($first->id)
        ->and($resolver->resolveForHost('globex.cboxid.com')?->environmentKey())->toBe($second->id)
        // Re-read, now that both are cached, to prove the entries did not collide.
        ->and($resolver->resolveForHost('acme.cboxid.com')?->environmentKey())->toBe($first->id)
        ->and($resolver->resolveForHost('globex.cboxid.com')?->environmentKey())->toBe($second->id);
});
