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
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Testing\RefreshDatabase;

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

    expect(fn () => $guard->assertAcceptable('short-one-123'))
        ->toThrow(PolicyViolation::class, 'at least 16 characters');

    // A conforming password passes without incident.
    $guard->assertAcceptable('a-long-enough-passphrase');
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
    $guard->assertAcceptable('a-perfectly-fine-passphrase');

    $policies->setForEnvironment(new AuthPolicy(minLength: 8, requireBreachCheck: true));
    expect(fn () => $guard->assertAcceptable('a-perfectly-fine-passphrase'))
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
