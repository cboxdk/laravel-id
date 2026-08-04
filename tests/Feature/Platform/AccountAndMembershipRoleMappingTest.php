<?php

declare(strict_types=1);

use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Platform\Enums\AccountRole;

/**
 * The correspondence between the two role enums, asserted rather than remembered.
 *
 * docs/core-concepts/account-and-membership-roles.md is the prose; this is the lock.
 * A new case in either enum, or a quietly widened predicate, turns these red — which
 * is the point, because the app maps between the two planes and every one of these
 * facts is the difference between a demotion and a privilege escalation.
 *
 * No mapping is shipped as code on purpose: a mapping is for one decision at one call
 * site, and a helper would invite persisting the result and re-deriving from it.
 */
it('shares four cases and differs by exactly one in each direction', function (): void {
    $account = array_map(fn (AccountRole $role): string => $role->value, AccountRole::cases());
    $membership = array_map(fn (MembershipRole $role): string => $role->value, MembershipRole::cases());

    sort($account);
    sort($membership);

    expect($account)->toBe(['admin', 'billing', 'developer', 'owner', 'viewer'])
        ->and($membership)->toBe(['admin', 'developer', 'member', 'owner', 'viewer'])
        // The shared four, and the one case each plane has alone.
        ->and(array_values(array_intersect($account, $membership)))->toBe(['admin', 'developer', 'owner', 'viewer'])
        ->and(array_values(array_diff($account, $membership)))->toBe(['billing'])
        ->and(array_values(array_diff($membership, $account)))->toBe(['member']);
});

it('agrees on who administers the entity', function (): void {
    $accountAdmins = array_values(array_filter(
        AccountRole::cases(),
        fn (AccountRole $role): bool => $role->canManageMembers(),
    ));
    $organizationAdmins = array_values(array_filter(
        MembershipRole::cases(),
        fn (MembershipRole $role): bool => $role->canManageOrganization(),
    ));

    expect(array_map(fn (AccountRole $r): string => $r->value, $accountAdmins))->toBe(['owner', 'admin'])
        ->and(array_map(fn (MembershipRole $r): string => $r->value, $organizationAdmins))->toBe(['owner', 'admin']);
});

/**
 * The trap the mapping doc exists to prevent: `canWrite()` is BROADER than
 * `canManageEnvironments()`. Mapping the account plane's Billing role onto Member —
 * the only membership case with no account-plane twin — would grant write access to a
 * role that is explicitly billing-only.
 */
it('does not let a membership write predicate stand in for environment management', function (): void {
    $writers = array_map(
        fn (MembershipRole $role): string => $role->value,
        array_values(array_filter(MembershipRole::cases(), fn (MembershipRole $role): bool => $role->canWrite())),
    );
    $environmentManagers = array_map(
        fn (AccountRole $role): string => $role->value,
        array_values(array_filter(AccountRole::cases(), fn (AccountRole $role): bool => $role->canManageEnvironments())),
    );

    expect($writers)->toBe(['owner', 'admin', 'developer', 'member'])
        ->and($environmentManagers)->toBe(['owner', 'admin', 'developer'])
        // `member` is the whole gap, and `Viewer` is therefore the safe floor for it.
        ->and(array_values(array_diff($writers, $environmentManagers)))->toBe(['member'])
        ->and(MembershipRole::Viewer->canWrite())->toBeFalse();
});

/**
 * Billing is not representable on the organization plane. Not "roughly Member", not
 * "roughly Admin" — absent. Anything that needs it must carry it separately.
 */
it('has no membership role that can manage billing', function (): void {
    expect(AccountRole::Billing->canManageBilling())->toBeTrue()
        ->and(AccountRole::Billing->canManageEnvironments())->toBeFalse()
        ->and(AccountRole::Billing->canReadMembers())->toBeFalse()
        // The demotion target: Viewer cannot write, so nothing is gained by the map…
        ->and(MembershipRole::Viewer->canWrite())->toBeFalse()
        // …and it keeps the half of Billing that anything actually asks for.
        ->and(MembershipRole::Viewer->canReadBilling())->toBeTrue()
        // Still absent, and deliberately so. Adding a billing case would arrive holding
        // `canWrite()` — "not a Viewer" — on every organization of every tenant, and
        // correcting that changes what write means for everybody. What is lost is
        // `canManageBilling()`, which no page and no route in the product asks for.
        ->and(method_exists(MembershipRole::class, 'canManageBilling'))->toBeFalse();
});

/**
 * The roster is PII, and BOTH planes now say so.
 *
 * This used to assert the opposite — that `MembershipRole` had no such predicate — and
 * that was the point: the gap was the reason a role could not simply be mapped across.
 * The gap is closed rather than worked around, because the restriction was never
 * account-specific. An organization's own admin console has exactly the same need: a
 * Developer is frequently a CI or agent credential rather than a person, and a leaked one
 * must not enumerate the team.
 *
 * The two lists are asserted separately, not compared, so a future change to one is a
 * visible decision rather than a silently-following consequence.
 */
it('restricts the roster on both planes, to the same shape', function (): void {
    $accountReaders = array_map(
        fn (AccountRole $role): string => $role->value,
        array_values(array_filter(AccountRole::cases(), fn (AccountRole $role): bool => $role->canReadMembers())),
    );
    $organizationReaders = array_map(
        fn (MembershipRole $role): string => $role->value,
        array_values(array_filter(MembershipRole::cases(), fn (MembershipRole $role): bool => $role->canReadMembers())),
    );

    expect($accountReaders)->toBe(['owner', 'admin', 'viewer'])
        ->and($organizationReaders)->toBe(['owner', 'admin', 'viewer'])
        // The two technical roles are the ones being kept out, on both planes.
        ->and(MembershipRole::Developer->canReadMembers())->toBeFalse()
        ->and(MembershipRole::Member->canReadMembers())->toBeFalse();
});

/**
 * `canWrite()` is still not environment management, now on both planes.
 *
 * The organization plane gained its own `canManageEnvironments()` rather than reusing
 * `canWrite()`, because `canWrite()` admits the generic Member — the role every person
 * placed in an organization carries by default — and standing up an environment grants a
 * live environment-admin session on that tenant's host.
 */
it('keeps environment management narrower than write on the organization plane', function (): void {
    $managers = array_map(
        fn (MembershipRole $role): string => $role->value,
        array_values(array_filter(MembershipRole::cases(), fn (MembershipRole $role): bool => $role->canManageEnvironments())),
    );

    expect($managers)->toBe(['owner', 'admin', 'developer'])
        ->and(MembershipRole::Member->canWrite())->toBeTrue()
        ->and(MembershipRole::Member->canManageEnvironments())->toBeFalse();
});

/**
 * The mapping itself, pinned case by case — the one definition of how the two
 * vocabularies line up, and the thing every later batch is measured against.
 */
it('maps every account role onto the organization plane', function (AccountRole $account, MembershipRole $expected): void {
    expect($account->asMembershipRole())->toBe($expected);
})->with([
    'owner' => [AccountRole::Owner, MembershipRole::Owner],
    'admin' => [AccountRole::Admin, MembershipRole::Admin],
    'developer' => [AccountRole::Developer, MembershipRole::Developer],
    'viewer' => [AccountRole::Viewer, MembershipRole::Viewer],
    // The one that loses something. See the test below for exactly what.
    'billing' => [AccountRole::Billing, MembershipRole::Viewer],
]);

/**
 * Ordering exists on one plane only. `AccountRole` has no `weight()`, so "highest role
 * wins" resolution cannot be run over account roles by reaching for the same method.
 */
it('orders membership roles and leaves account roles unordered', function (): void {
    expect(MembershipRole::Owner->outranks(MembershipRole::Admin))->toBeTrue()
        ->and(MembershipRole::Developer->outranks(MembershipRole::Member))->toBeTrue()
        ->and(MembershipRole::Member->outranks(MembershipRole::Viewer))->toBeTrue()
        ->and(MembershipRole::Viewer->outranks(MembershipRole::Viewer))->toBeFalse()
        ->and(method_exists(AccountRole::class, 'weight'))->toBeFalse()
        // …and only the account plane withholds Owner from assignment.
        ->and(array_map(fn (AccountRole $r): string => $r->value, AccountRole::assignable()))
        ->toBe(['admin', 'billing', 'developer', 'viewer']);
});
