<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\EnvironmentResolutionCache;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\TenantProvisioner;
use Cbox\Id\Platform\ValueObjects\TenantBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['cbox-id.environments.base_domains' => ['cboxid.com']]);
});

function resolutionEnvironment(string $slugSeed = 'Acme'): Environment
{
    platformRootEnvironment();

    return app(TenantProvisioner::class)->provision(new TenantBlueprint(
        organizationName: $slugSeed,
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

    // Cold path: the custom-domain lookup misses, the slug lookup hits, then ownership
    // is walked — the environment's project, and that project's organization — and the
    // owner's liveness read. FOUR round trips on EVERY uncached request, before any
    // endpoint logic runs.
    //
    // It was three. The fourth is the price of removing `environments.account_id`, a
    // denormalized copy of ownership that made the liveness check a single read. The copy
    // is what made it cheap, and a copy of ownership is a second place for ownership to be
    // wrong — so the hop is bought deliberately, and the cache is what keeps it off the
    // hot path. The number is asserted rather than bounded precisely so that buying
    // another one has to be a decision somebody writes down.
    expect($cold)->toBe(4)
        ->and($warm)->toBe(0)
        ->and($resolver->resolveForHost('acme.cboxid.com')?->environmentKey())->toBe($env->id);
});

it('keeps resolving live when the cache is turned off', function (): void {
    resolutionEnvironment();
    config(['cbox-id.environments.resolution_cache_ttl' => 0]);

    $resolver = app(EnvironmentResolver::class);
    $resolver->resolveForHost('acme.cboxid.com');

    // The same FOUR the cold path pays, statement for statement: a warmed request costs
    // full live resolution when the cache is off, which is the whole property. It was
    // three for the same reason the cold budget was — `environments.account_id` made the
    // liveness check a single read. Nothing here caches, so there is no second number
    // this could have become.
    expect(queriesDuring(fn () => $resolver->resolveForHost('acme.cboxid.com')))->toBe(4);
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
    // this only works because the organization writer invalidates explicitly.
    suspendOwnerOf($env);
    expect($resolver->resolveForHost('acme.cboxid.com'))->toBeNull();

    reactivateOwnerOf($env);
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

/**
 * THE ONE ANSWER THAT WAS NEVER CACHED WAS THE CHEAPEST TO ASK FOR.
 *
 * A host mapping to no environment took the full resolution — the custom-domain miss,
 * the slug miss, the liveness walk — on every request, forever, while every real tenant's
 * host cost nothing. Point a wildcard DNS record or a scanner at the platform and each
 * request bought database round trips against the table the whole platform resolves
 * through.
 */
it('stops re-resolving a host that maps to nothing', function (): void {
    resolutionEnvironment();
    $resolver = app(EnvironmentResolver::class);

    $cold = queriesDuring(fn () => $resolver->resolveForHost('nobody.cboxid.com'));
    $warm = queriesDuring(fn () => $resolver->resolveForHost('nobody.cboxid.com'));

    expect($cold)->toBeGreaterThan(0)
        ->and($warm)->toBe(0)
        // And still nothing — a cached absence must answer the same as a live one.
        ->and($resolver->resolveForHost('nobody.cboxid.com'))->toBeNull();
});

/**
 * The bound on that memory. Suspension must keep cutting traffic on the very next
 * request — which it does, because it forgets the `env:` entry and a host mapping with
 * no environment behind it falls through to a live resolution — and reactivation must
 * keep restoring it on the next request rather than ten seconds later, which is why the
 * account writer forgets the HOSTS as well as the environments.
 *
 * The two tests above already hold both directions; this holds the thing that would
 * silently break them: a refusal must never be remembered under the positive TTL.
 */
it('remembers a refusal for a fraction of the time it remembers a hit', function (): void {
    expect(EnvironmentResolutionCache::ABSENT_TTL)
        ->toBeLessThan(EnvironmentResolutionCache::DEFAULT_TTL);
});
