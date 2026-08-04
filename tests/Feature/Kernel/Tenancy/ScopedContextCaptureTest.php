<?php

declare(strict_types=1);

use Cbox\Id\Console\HealthChecks;
use Cbox\Id\Directory\DirectoryConnectors;
use Cbox\Id\Identity\Hashing\HashVerifierRegistry;
use Cbox\Id\Kernel\Runtime\RequestLifetime;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Otp\ChannelRegistry;
use Cbox\Id\Provisioning\HttpScimClient;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * A `singleton` must never constructor-inject a `scoped` context.
 *
 * `EnvironmentContext` and `TenantContext` are bound with `scoped()`. A queue worker
 * calls `forgetScopedInstances()` between jobs, which unsets the BINDING but does not
 * reset an object a singleton is already holding — so a singleton that captured one at
 * construction keeps the FIRST job's environment for the life of the process. Job B is
 * then written, read, keyed or delivered under job A's tenant.
 *
 * `EnvironmentScope::apply()` has carried a comment stating this rule ("Resolve the
 * context LAZILY, per query — never capture it") for a long time. It was violated four
 * separate times anyway: DatabaseEventBus, DatabaseAuditLog, DatabaseKeyManager and
 * DatabaseExternalActions. That is the argument for a test rather than more prose.
 *
 * The fix in every case is {@see ResolvesEnvironment}
 * (or an equivalent per-call `app()` resolve), which is why the trait exists — the
 * correct pattern should also be the shortest one.
 */

/**
 * The scoped contracts a singleton may not hold on to.
 *
 * @return list<class-string>
 */
function scopedContracts(): array
{
    return [EnvironmentContext::class, TenantContext::class];
}

/**
 * Every SHARED (singleton) binding in the booted container, resolved, paired with the
 * bindings that could not be resolved at all.
 *
 * @return array{inspected: array<string, object>, unresolvable: list<string>}
 */
function resolvedSingletons(): array
{
    $inspected = [];
    $unresolvable = [];

    foreach (array_keys(app()->getBindings()) as $abstract) {
        $binding = app()->getBindings()[$abstract] ?? null;

        if (! is_array($binding) || ($binding['shared'] ?? false) !== true) {
            continue;
        }

        if (! is_string($abstract)) {
            continue;
        }

        // A scoped binding is ALSO `shared` in Laravel's container — it is a singleton
        // that gets flushed between jobs. The contexts themselves are the things being
        // captured, not the captors, so they are not candidates.
        if (in_array($abstract, scopedContracts(), true)) {
            continue;
        }

        try {
            $instance = app()->make($abstract);
        } catch (Throwable) {
            $unresolvable[] = $abstract;

            continue;
        }

        if (is_object($instance)) {
            $inspected[$abstract] = $instance;
        }
    }

    return ['inspected' => $inspected, 'unresolvable' => $unresolvable];
}

/**
 * @return list<string> the scoped contracts $instance captures at construction
 */
function capturedScopedContracts(object $instance): array
{
    $constructor = (new ReflectionClass($instance))->getConstructor();

    if ($constructor === null) {
        return [];
    }

    $captured = [];

    foreach ($constructor->getParameters() as $parameter) {
        $type = $parameter->getType();

        // Union/intersection types are still worth checking, so walk every named leg.
        $legs = $type instanceof ReflectionNamedType
            ? [$type]
            : array_filter(
                $type instanceof ReflectionUnionType || $type instanceof ReflectionIntersectionType ? $type->getTypes() : [],
                fn (mixed $t): bool => $t instanceof ReflectionNamedType,
            );

        foreach ($legs as $leg) {
            $name = $leg->getName();

            foreach (scopedContracts() as $contract) {
                // is_a(..., true): catches the CONCRETE manager too
                // (EnvironmentContextManager), not just the contract.
                if (class_exists($name) || interface_exists($name)) {
                    if (is_a($name, $contract, true)) {
                        $captured[] = $contract;
                    }
                }
            }
        }
    }

    return array_values(array_unique($captured));
}

it('never lets a singleton constructor-inject a scoped tenancy context', function (): void {
    ['inspected' => $inspected, 'unresolvable' => $unresolvable] = resolvedSingletons();

    // GUARD AGAINST THIS TEST BECOMING HOLLOW. If resolution starts failing wholesale
    // (a refactor, a provider reorder), the loop below would iterate nothing and pass
    // green while checking NOTHING — which is exactly the failure mode this whole
    // exercise is about. The floor is well under the ~90 singletons the package binds,
    // so it will not flap, but it will catch an empty set.
    expect(count($inspected))->toBeGreaterThan(40,
        'The architecture test inspected almost no singletons — it is not proving anything. '
        .'Unresolvable bindings: '.implode(', ', $unresolvable));

    $violations = [];

    foreach ($inspected as $abstract => $instance) {
        $captured = capturedScopedContracts($instance);

        if ($captured !== []) {
            $violations[] = $abstract.' → '.$instance::class.' captures '.implode(', ', $captured);
        }
    }

    expect($violations)->toBe([],
        "A singleton constructor-injected a scoped tenancy context.\n\n"
        .implode("\n", $violations)
        ."\n\nA queue worker's forgetScopedInstances() unsets the BINDING but does not reset an "
        ."object the singleton already holds, so this keeps the first job's tenant for the life "
        .'of the process. Resolve it per call instead — use the ResolvesEnvironment trait.');
});

it('catches a violation when one is introduced', function (): void {
    // The test above can only be trusted if a real violation makes capturedScopedContracts()
    // fire. Prove it against a class shaped exactly like the four that were fixed, rather
    // than trusting that the reflection walk works.
    $captor = new class(app(EnvironmentContext::class))
    {
        public function __construct(private readonly EnvironmentContext $environments) {}
    };

    expect(capturedScopedContracts($captor))->toBe([EnvironmentContext::class]);

    // …and that a lazily-resolving class of the same shape does NOT fire.
    $lazy = new class
    {
        public function environments(): EnvironmentContext
        {
            return app(EnvironmentContext::class);
        }
    };

    expect(capturedScopedContracts($lazy))->toBe([]);
});

/*
|--------------------------------------------------------------------------
| The second half of the same mistake: a singleton that MEMOISES
|--------------------------------------------------------------------------
| Capturing a scoped context is one way to give a per-request answer a per-process
| life. Keeping the answer itself in a mutable property is the other, and it went
| unnoticed for longer because it reads as an optimisation rather than as state.
| `EnvironmentIssuerResolver` and `DatabaseAuthPolicies` each carried a docblock
| saying "memoized per request (the binding is a singleton)" — two clauses that
| contradict each other, sat next to each other, for months.
|
| The consequences run in the dangerous direction. A tenant verifies a custom domain
| and a warm worker keeps minting tokens with the old `iss`. An operator switches the
| MFA mandate on and a warm worker keeps serving the looser policy. Neither surfaces
| as an error; both are invisible on php-fpm, where the process ends with the request.
| This package is distributed and does not get to assume php-fpm.
|
| Rebinding the holder `scoped` is the obvious fix and it is usually WRONG here: every
| one of these is constructor-injected into other singletons, and
| `forgetScopedInstances()` unsets the binding without reaching an instance somebody
| already holds. The fix that works whoever holds the memo is `RequestLifetime`.
*/

/**
 * Singletons whose mutable array is not request state.
 *
 * A REGISTRY is the legitimate case: it is filled at boot from providers and config,
 * describes the deployment rather than the request, and living for the process is the
 * point. Each entry carries why, because an allow-list nobody has to justify an addition
 * to is how this test stops meaning anything.
 *
 * @return array<class-string, string>
 */
function memoExemptSingletons(): array
{
    return [
        // Filled at boot by service providers; the set of checks is a fact about the
        // deployment, not about who is asking.
        HealthChecks::class => 'boot-time registry of health checks',
        DirectoryConnectors::class => 'boot-time registry of directory connectors',
        HashVerifierRegistry::class => 'boot-time registry of legacy hash verifiers',
        ChannelRegistry::class => 'boot-time registry of OTP channels, plus their resolved instances',
        // Not a memo of a decision — a cache of a short-lived OAuth token with its own
        // expiry, keyed by connection, explicitly written to outlive a job. See the
        // property's docblock: a cache with NO expiry there is the bug it guards against.
        HttpScimClient::class => 'per-connection OAuth token cache, expiry-aware by construction',
    ];
}

/**
 * @return list<string> the mutable array properties $instance holds
 */
function mutableArrayProperties(object $instance): array
{
    $held = [];

    foreach ((new ReflectionClass($instance))->getProperties() as $property) {
        if ($property->isStatic() || $property->isReadOnly()) {
            continue;
        }

        $type = $property->getType();

        if ($type instanceof ReflectionNamedType && $type->getName() === 'array') {
            $held[] = $property->getName();
        }
    }

    return $held;
}

/** Whether $instance compares a held {@see RequestLifetime} against the container's. */
function guardsItsMemoWithRequestLifetime(object $instance): bool
{
    foreach ((new ReflectionClass($instance))->getProperties() as $property) {
        $type = $property->getType();

        if ($type instanceof ReflectionNamedType && is_a($type->getName(), RequestLifetime::class, true)) {
            return true;
        }
    }

    return false;
}

it('never lets a singleton memoise request state with nothing to invalidate it', function (): void {
    ['inspected' => $inspected] = resolvedSingletons();

    // Same floor as the test above, and for the same reason: a loop over an empty set
    // passes green while proving nothing.
    expect(count($inspected))->toBeGreaterThan(40);

    $scoped = (function (): array {
        // A `scoped` binding is also `shared`, so the two are indistinguishable from
        // getBindings() alone. The container tracks the scoped abstracts separately and
        // that list is the only honest source; read it rather than inferring.
        $property = new ReflectionProperty(app(), 'scopedInstances');

        /** @var list<string> $abstracts */
        $abstracts = $property->getValue(app());

        return $abstracts;
    })();

    $violations = [];

    foreach ($inspected as $abstract => $instance) {
        // Ours only. A framework or Testbench singleton holding an array is not this
        // package's invariant to enforce, and flagging it would push the real finding
        // off the end of the message.
        if (! str_starts_with($instance::class, 'Cbox\\Id\\')) {
            continue;
        }

        // Scoped bindings are dropped between requests already — that IS the mechanism,
        // as long as nothing captures them, which the test above is what enforces.
        if (in_array($abstract, $scoped, true)) {
            continue;
        }

        if (array_key_exists($instance::class, memoExemptSingletons())) {
            continue;
        }

        $held = mutableArrayProperties($instance);

        if ($held === [] || guardsItsMemoWithRequestLifetime($instance)) {
            continue;
        }

        $violations[] = $abstract.' → '.$instance::class.' holds $'.implode(', $', $held);
    }

    expect($violations)->toBe([],
        "A singleton holds mutable array state with nothing to invalidate it between requests.\n\n"
        .implode("\n", $violations)
        ."\n\nA singleton lives for the PROCESS, so a memo on one outlives the request it was "
        .'computed in — invisible on php-fpm, wrong for the life of an Octane worker. Hold a '
        .RequestLifetime::class.' and compare it per call (see CachedEntitlements), or, if the '
        .'array really is boot-time configuration rather than request state, add the class to '
        .'memoExemptSingletons() with the reason.');
});

/**
 * …and the same property BEHAVIOURALLY, because the test above only checks a shape.
 *
 * A class could hold a {@see RequestLifetime} and never compare it, and the reflection
 * sweep would be satisfied. So: fill the memo, cross a request boundary the way a
 * long-running worker does, and ask THE SAME INSTANCE again.
 *
 * `forgetScopedInstances()` is exactly what Octane calls between requests and what the
 * queue calls between jobs. The instance is deliberately held across the call — that is
 * the whole scenario, and it is what `scoped()` alone would not have fixed: three
 * singletons constructor-inject this resolver, so in production somebody is always
 * holding it.
 */
it('drops a singleton memo once the request that filled it has ended', function (): void {
    config([
        'cbox-id.environments.base_domains' => ['cboxid.com'],
        'cbox-id.issuer' => 'https://cboxid.com',
    ]);

    $environment = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);

    // Whoever captured the resolver keeps THIS object for the life of the process.
    $captured = app(IssuerResolver::class);

    expect($captured->forEnvironment($environment->id))->toBe('https://acme.cboxid.com');

    // The tenant verifies a custom domain. Their issuer identity changes.
    $environment->forceFill(['domain' => 'id.acme.com', 'domain_verified_at' => now()])->save();

    // Still the same request: the memo is doing its job, and answering the old value here
    // is correct rather than a bug — a resolver that re-queried mid-request would just be
    // a resolver with no memo.
    expect($captured->forEnvironment($environment->id))->toBe('https://acme.cboxid.com');

    app()->forgetScopedInstances();

    expect($captured->forEnvironment($environment->id))->toBe(
        'https://id.acme.com',
        'The captured resolver kept the previous request\'s issuer. On Octane that worker '
        .'goes on minting tokens with an `iss` the tenant no longer publishes, while a cold '
        .'worker serves the new one from discovery — so relying-party validation fails on '
        .'a fraction of requests and on no reproducible pattern.',
    );
})->group('security');
