<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\BreachedPasswordCheck;
use Cbox\Id\Identity\Contracts\PasswordPolicyGuard;
use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\Enums\SsoEnforcement;
use Cbox\Id\Identity\Exceptions\PolicyViolation;
use Cbox\Id\Identity\NeverBreachedCheck;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('falls back to a safe default when no policy is stored', function (): void {
    $policy = app(AuthPolicies::class)->resolve();

    expect($policy->minLength)->toBe(12)
        ->and($policy->requireBreachCheck)->toBeTrue()
        ->and($policy->mfa)->toBe(MfaRequirement::Optional)
        ->and($policy->sso)->toBe(SsoEnforcement::Off);
});

it('resolves the environment baseline when an organization has no override', function (): void {
    $policies = app(AuthPolicies::class);
    $policies->setForEnvironment(new AuthPolicy(minLength: 16, mfa: MfaRequirement::Required));

    expect($policies->resolve('org_1')->minLength)->toBe(16)
        ->and($policies->resolve('org_1')->mfa)->toBe(MfaRequirement::Required)
        ->and($policies->overrideFor('org_1'))->toBeNull();
});

// The invariant the whole design rests on: a tenant may demand MORE of its own people
// than the operator requires, never less.
it('lets an organization tighten the environment baseline', function (): void {
    $policies = app(AuthPolicies::class);
    $policies->setForEnvironment(new AuthPolicy(minLength: 12, mfa: MfaRequirement::Optional, maxAgeDays: 180));
    $policies->setForOrganization('org_strict', new AuthPolicy(
        minLength: 20,
        mfa: MfaRequirement::Required,
        maxAgeDays: 30,
        sso: SsoEnforcement::Required,
    ));

    $effective = $policies->resolve('org_strict');

    expect($effective->minLength)->toBe(20)
        ->and($effective->mfa)->toBe(MfaRequirement::Required)
        ->and($effective->maxAgeDays)->toBe(30)
        ->and($effective->sso)->toBe(SsoEnforcement::Required);
});

it('refuses to let an organization loosen the environment baseline', function (): void {
    $policies = app(AuthPolicies::class);
    $policies->setForEnvironment(new AuthPolicy(
        minLength: 16,
        requireBreachCheck: true,
        maxAgeDays: 60,
        reuseHistory: 5,
        mfa: MfaRequirement::Required,
        sso: SsoEnforcement::Preferred,
    ));

    // An override that asks for LESS on every axis.
    $policies->setForOrganization('org_lax', new AuthPolicy(
        minLength: 8,
        requireBreachCheck: false,
        maxAgeDays: 3650,
        reuseHistory: 0,
        mfa: MfaRequirement::Off,
        sso: SsoEnforcement::Off,
    ));

    $effective = $policies->resolve('org_lax');

    // Every field holds the environment's stricter value.
    expect($effective->minLength)->toBe(16)
        ->and($effective->requireBreachCheck)->toBeTrue()
        ->and($effective->maxAgeDays)->toBe(60)
        ->and($effective->reuseHistory)->toBe(5)
        ->and($effective->mfa)->toBe(MfaRequirement::Required)
        ->and($effective->sso)->toBe(SsoEnforcement::Preferred);
});

it('restores the baseline when an override is cleared', function (): void {
    $policies = app(AuthPolicies::class);
    $policies->setForEnvironment(new AuthPolicy(minLength: 12));
    $policies->setForOrganization('org_temp', new AuthPolicy(minLength: 24));
    expect($policies->resolve('org_temp')->minLength)->toBe(24);

    $policies->clearForOrganization('org_temp');
    expect($policies->resolve('org_temp')->minLength)->toBe(12)
        ->and($policies->overrideFor('org_temp'))->toBeNull();
});

it('enforces the minimum length on a proposed password', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(minLength: 16, requireBreachCheck: false));
    $guard = app(PasswordPolicyGuard::class);

    expect(fn () => $guard->assertAcceptableForNewSubject('short-one-123'))
        ->toThrow(PolicyViolation::class, 'at least 16 characters');

    // A conforming password passes without incident.
    $guard->assertAcceptableForNewSubject('a-long-enough-passphrase');
});

it('refuses a breached password only when the policy asks for the check', function (): void {
    // A host-supplied checker that considers everything breached.
    app()->instance(BreachedPasswordCheck::class, new class implements BreachedPasswordCheck
    {
        public function isBreached(string $password): bool
        {
            return true;
        }
    });

    $policies = app(AuthPolicies::class);
    $guard = app(PasswordPolicyGuard::class);

    $policies->setForEnvironment(new AuthPolicy(minLength: 8, requireBreachCheck: false));
    $guard->assertAcceptableForNewSubject('a-perfectly-fine-passphrase');

    $policies->setForEnvironment(new AuthPolicy(minLength: 8, requireBreachCheck: true));
    expect(fn () => $guard->assertAcceptableForNewSubject('a-perfectly-fine-passphrase'))
        ->toThrow(PolicyViolation::class, 'public data breach');
});

it('refuses reuse of a recently-used password within the configured depth', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(
        minLength: 8,
        requireBreachCheck: false,
        reuseHistory: 2,
    ));

    $guard = app(PasswordPolicyGuard::class);
    $hasher = app(Hasher::class);

    $guard->remember('user_1', $hasher->make('the-first-passphrase'));
    $guard->remember('user_1', $hasher->make('the-second-passphrase'));

    // Both retained passwords are refused for this subject...
    expect(fn () => $guard->assertAcceptable('the-first-passphrase', 'user_1'))
        ->toThrow(PolicyViolation::class, 'used recently');
    expect(fn () => $guard->assertAcceptable('the-second-passphrase', 'user_1'))
        ->toThrow(PolicyViolation::class, 'used recently');

    // ...but a fresh one is fine, and another subject is unaffected.
    $guard->assertAcceptable('a-brand-new-passphrase', 'user_1');
    $guard->assertAcceptable('the-first-passphrase', 'user_2');
});

it('prunes history beyond the depth the policy compares against', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(
        minLength: 8,
        requireBreachCheck: false,
        reuseHistory: 1,
    ));

    $guard = app(PasswordPolicyGuard::class);
    $hasher = app(Hasher::class);

    $guard->remember('user_prune', $hasher->make('the-oldest-passphrase'));
    $guard->remember('user_prune', $hasher->make('the-newest-passphrase'));

    // Only the most recent is retained, so the older one is usable again — the store
    // never keeps more credentials than the policy actually needs.
    expect(fn () => $guard->assertAcceptable('the-newest-passphrase', 'user_prune'))
        ->toThrow(PolicyViolation::class);
    $guard->assertAcceptable('the-oldest-passphrase', 'user_prune');
});

it('ships a breach check that claims nothing rather than pretending', function (): void {
    // The default must not silently answer "not breached" as though it had looked.
    expect(app(BreachedPasswordCheck::class))
        ->toBeInstanceOf(NeverBreachedCheck::class)
        ->and(app(BreachedPasswordCheck::class)->isBreached('password'))->toBeFalse();
});

/**
 * The per-request memo is a singleton, and one process legitimately visits several
 * environments: a queue worker draining jobs for different tenants, and every
 * `PlatformRoot::run()` that steps into tenant 1 and back. An unkeyed memo answered the
 * FIRST environment's policy for all of them — applying one tenant's password floor to
 * another's people, in the direction the tighten-only rule exists to forbid.
 */
it('does not carry one environment memoized policy into another', function (): void {
    $context = app(EnvironmentContext::class);
    $policies = app(AuthPolicies::class);

    $lax = GenericEnvironment::of('env_lax');
    $strict = GenericEnvironment::of('env_strict');

    $context->runAs($lax, fn () => $policies->setForEnvironment(new AuthPolicy(minLength: 12)));
    $context->runAs($strict, fn () => $policies->setForEnvironment(new AuthPolicy(minLength: 32)));

    // Warm the memo on the lax environment first, then step into the strict one.
    expect($context->runAs($lax, fn (): int => $policies->forEnvironment()->minLength))->toBe(12)
        ->and($context->runAs($strict, fn (): int => $policies->forEnvironment()->minLength))->toBe(32)
        ->and($context->runAs($lax, fn (): int => $policies->forEnvironment()->minLength))->toBe(12);
});

/**
 * The optional `$userId` used to buy a caller a weaker check for free: no reuse history,
 * and the bare environment baseline instead of the organizations that bind the subject.
 * An exemption reachable by forgetting an argument looks identical to the case where it
 * is correct, so the two cases are now different methods and the subject has no default.
 */
it('names the no-subject case rather than letting a caller omit one', function (): void {
    $reflection = new ReflectionMethod(PasswordPolicyGuard::class, 'assertAcceptable');
    $userId = $reflection->getParameters()[1];

    expect($userId->getName())->toBe('userId')
        ->and($userId->isOptional())->toBeFalse()
        ->and($userId->getType()?->allowsNull() ?? true)->toBeFalse();
});

/**
 * `overrideFor()` is the one policy read that happens in a LOOP.
 *
 * PasswordExpiry and MfaMandate both walk the signed-in subject's memberships asking for
 * each organization's override, and the host calls them from its authentication
 * middleware — which is also persistent Livewire middleware, so it runs again on every
 * round trip. Unmemoised, that was two queries per organization on every single request,
 * while `forEnvironment()` four lines above had been memoised from the start.
 *
 * Counting queries rather than asserting on an internal property: the guarantee is "the
 * database is asked once", not "there is a private array". And comparing two loop sizes
 * rather than pinning a number — the property that matters is that the cost does not
 * grow with the number of reads, which is exactly what a fixed expectation would stop
 * describing the moment an unrelated read was added.
 */
it('reads an organization override once per request, not once per call', function (): void {
    $policies = app(AuthPolicies::class);
    $policies->setForOrganization('org_hot', new AuthPolicy(minLength: 20));

    $cost = function (int $rounds) use ($policies): int {
        // Warm both memos first, then measure. The claim under test is "having read it
        // once, never read it again" — counting the first read too would just be
        // measuring how many memos exist.
        $policies->overrideFor('org_hot');
        $policies->resolve('org_hot');

        DB::flushQueryLog();
        DB::enableQueryLog();

        for ($i = 0; $i < $rounds; $i++) {
            $policies->overrideFor('org_hot');
            $policies->resolve('org_hot');
        }

        $reads = count(array_filter(
            DB::getQueryLog(),
            fn (array $entry): bool => str_contains((string) $entry['query'], 'select') && str_contains((string) $entry['query'], 'auth_policies'),
        ));
        DB::disableQueryLog();

        return $reads;
    };

    $few = $cost(5);
    $many = $cost(50);

    expect([$few, $many])->toBe([0, 0], "policy reads scale with call count: {$few} at 5 rounds, {$many} at 50");
});

/**
 * A memo that outlives its write is a policy that did not take effect. This is the half
 * of memoisation that actually needs proving.
 */
it('sees a policy change made after it was first read', function (): void {
    $policies = app(AuthPolicies::class);
    $policies->setForEnvironment(new AuthPolicy(minLength: 8));

    expect($policies->overrideFor('org_fresh'))->toBeNull();

    $policies->setForOrganization('org_fresh', new AuthPolicy(minLength: 30));
    expect($policies->overrideFor('org_fresh')?->minLength)->toBe(30);

    $policies->setForOrganization('org_fresh', new AuthPolicy(minLength: 40));
    expect($policies->overrideFor('org_fresh')?->minLength)->toBe(40);

    $policies->clearForOrganization('org_fresh');
    expect($policies->overrideFor('org_fresh'))->toBeNull();
});

/**
 * One process legitimately visits several environments — a queue worker draining jobs for
 * different tenants, every PlatformRoot::run() that steps in and back. An unkeyed memo
 * would answer the first environment's override for all of them, applying one tenant's
 * password floor to another's people.
 */
it('does not answer one environment\'s override in another', function (): void {
    $policies = app(AuthPolicies::class);
    $environments = app(EnvironmentContext::class);

    $environments->runAs(GenericEnvironment::of('env_one'), function () use ($policies): void {
        $policies->setForOrganization('org_shared', new AuthPolicy(minLength: 25));
        expect($policies->overrideFor('org_shared')?->minLength)->toBe(25);
    });

    $environments->runAs(GenericEnvironment::of('env_two'), function () use ($policies): void {
        expect($policies->overrideFor('org_shared'))->toBeNull('a memo leaked across environments');
    });
});

/**
 * The batch read is the actual fix for the loop. Memoising `overrideFor()` removed the
 * DUPLICATE reads — two per organization down to one — but not the shape: a subject in
 * nine organizations still cost nine queries on every authenticated request.
 */
it('reads every organization override in one query', function (): void {
    $policies = app(AuthPolicies::class);
    $ids = [];

    foreach (range(1, 12) as $i) {
        $ids[] = $id = "org_batch_{$i}";

        // Only half have an override, so the absence path is exercised too.
        if ($i % 2 === 0) {
            $policies->setForOrganization($id, new AuthPolicy(minLength: 10 + $i));
        }
    }

    DB::flushQueryLog();
    DB::enableQueryLog();
    $found = $policies->overridesFor($ids);
    $first = count(DB::getQueryLog());

    // Again, now that every one of them is memoised — including the absences, or a
    // subject with no overrides re-reads all twelve on the next request.
    DB::flushQueryLog();
    $policies->overridesFor($ids);
    $second = count(DB::getQueryLog());
    DB::disableQueryLog();

    expect($found)->toHaveCount(6)
        ->and($first)->toBe(1, "twelve organizations cost {$first} queries")
        ->and($second)->toBe(0, "a second read cost {$second} queries");
});
