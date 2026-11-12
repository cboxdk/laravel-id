<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Platform\TenantProvisioner;
use Cbox\Id\Platform\ValueObjects\TenantBlueprint;
use Illuminate\Cache\Events\RetrievingKey;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;

uses(RefreshDatabase::class);

/*
 * What a request reads before its endpoint runs.
 *
 * WHY THIS FILE EXISTS. Measured on production (2026-11-12): a cache read is a round trip
 * of about 1 ms and a query one of 1.2 ms or more, and every request resolved its
 * environment from the cache and then asked the database for the same row again to name
 * the issuer. One discovery request read the default environment from the cache four
 * times. These tests hold the counts: the same question is asked once per request.
 */
beforeEach(function (): void {
    config(['cbox-id.environments.base_domains' => ['cboxid.com']]);
});

function requestPathEnvironment(): Environment
{
    platformRootEnvironment();

    return app(TenantProvisioner::class)->provision(new TenantBlueprint(
        organizationName: 'Acme',
        ownerEmail: 'acme@test.test',
        ownerName: 'Owner',
        ownerPassword: 'supersecret123',
    ))->environment;
}

/** @return array{queries: int, reads: list<string>} */
function readsDuring(Closure $callback): array
{
    $queries = 0;
    $reads = [];
    DB::listen(function () use (&$queries): void {
        $queries++;
    });
    Event::listen(RetrievingKey::class, function (RetrievingKey $event) use (&$reads): void {
        $reads[] = $event->key;
    });

    $callback();

    return ['queries' => $queries, 'reads' => $reads];
}

it('names the issuer from the environment the request already resolved, without a query', function (): void {
    $environment = requestPathEnvironment();
    $resolved = app(EnvironmentResolver::class)->resolveForHost('acme.cboxid.com');
    app(EnvironmentContext::class)->set($resolved);

    $reads = readsDuring(fn () => expect(app(IssuerResolver::class)->issuer())->toBe('https://acme.cboxid.com'));

    expect($resolved?->environmentKey())->toBe($environment->id)
        ->and($reads['queries'])->toBe(0);
});

it('still reads the row for an environment the request is not in', function (): void {
    $environment = requestPathEnvironment();

    $reads = readsDuring(fn () => expect(app(IssuerResolver::class)->forEnvironment($environment->id))->toBe('https://acme.cboxid.com'));

    expect($reads['queries'])->toBe(1);
});

it('knows the platform root from the request\'s own environment when that is the root', function (): void {
    $root = platformRootEnvironment();
    app(EnvironmentContext::class)->set($root);

    $reads = readsDuring(fn () => expect(app(PlatformRoot::class)->model()?->id)->toBe($root->id));

    expect($reads['queries'])->toBe(0);
});

it('asks the cache once per request for the same host and for the default environment', function (): void {
    requestPathEnvironment();
    $resolver = app(EnvironmentResolver::class);
    // Warm the shared cache, then start a new request.
    $resolver->resolveForHost('acme.cboxid.com');
    $resolver->resolveForHost('nobody.cboxid.com');
    $resolver->defaultEnvironment();
    app()->forgetScopedInstances();

    $reads = readsDuring(function () use ($resolver): void {
        foreach ([1, 2, 3, 4] as $_) {
            $resolver->resolveForHost('acme.cboxid.com');
            $resolver->resolveForHost('nobody.cboxid.com');
            $resolver->defaultEnvironment();
        }
    });

    // Host and environment for the mapped host, one read for the unmapped one, one for the default.
    expect($reads['queries'])->toBe(0)
        ->and($reads['reads'])->toHaveCount(4);
});

it('forgets what it remembered when the environment changes inside the request', function (): void {
    $environment = requestPathEnvironment();
    $resolver = app(EnvironmentResolver::class);
    $resolver->resolveForHost('acme.cboxid.com');

    $environment->forceFill(['domain' => 'login.acme.test', 'domain_verified_at' => now()])->save();

    expect($resolver->resolveForHost('login.acme.test')?->environmentKey())->toBe($environment->id)
        ->and($resolver->resolveForHost('acme.cboxid.com')?->domain)->toBe('login.acme.test');
});

it('asks again on the next request', function (): void {
    requestPathEnvironment();
    $resolver = app(EnvironmentResolver::class);
    $resolver->defaultEnvironment();
    app()->forgetScopedInstances();
    $resolver->defaultEnvironment();
    app()->forgetScopedInstances();

    $reads = readsDuring(fn () => $resolver->defaultEnvironment());

    expect($reads['reads'])->toHaveCount(1);
});
