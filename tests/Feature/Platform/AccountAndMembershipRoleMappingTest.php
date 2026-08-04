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
        // The demotion target: Viewer cannot write, so nothing is gained by the map.
        ->and(MembershipRole::Viewer->canWrite())->toBeFalse()
        ->and(method_exists(MembershipRole::class, 'canManageBilling'))->toBeFalse();
});

/**
 * The roster is PII. A Developer on the account plane is a technical credential and is
 * refused it; the organization plane has no such predicate at all, which is exactly
 * why mapping a role across cannot be assumed to preserve the restriction.
 */
it('keeps the account roster restricted where the organization plane has no opinion', function (): void {
    $readers = array_map(
        fn (AccountRole $role): string => $role->value,
        array_values(array_filter(AccountRole::cases(), fn (AccountRole $role): bool => $role->canReadMembers())),
    );

    expect($readers)->toBe(['owner', 'admin', 'viewer'])
        ->and(method_exists(MembershipRole::class, 'canReadMembers'))->toBeFalse();
});

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
