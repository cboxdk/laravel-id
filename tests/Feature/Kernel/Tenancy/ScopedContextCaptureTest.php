<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;

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
