<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Enums;

use Cbox\Id\Organization\Enums\MembershipRole;

/**
 * A member's role on the account — the buyer plane's RBAC, modelled on Stripe's
 * team roles. Capabilities are deny-by-default: a role grants only what its methods
 * return true for. Distinct from the federated, app-declared RBAC that governs
 * end-users inside an environment; this governs who can administer the ACCOUNT.
 */
enum AccountRole: string
{
    /** Full control, including billing, members, and destructive account actions. */
    case Owner = 'owner';

    /** Manage members, environments, and billing — everything short of owning the account. */
    case Admin = 'admin';

    /** Billing and plan only. */
    case Billing = 'billing';

    /** Create and manage environments (the technical plane); no members or billing. */
    case Developer = 'developer';

    /** Read-only across the account. */
    case Viewer = 'viewer';

    public function label(): string
    {
        return match ($this) {
            self::Owner => 'Owner',
            self::Admin => 'Admin',
            self::Billing => 'Billing',
            self::Developer => 'Developer',
            self::Viewer => 'Read-only',
        };
    }

    public function description(): string
    {
        return match ($this) {
            self::Owner => 'Full control, including billing and members.',
            self::Admin => 'Manage environments, members, and billing.',
            self::Billing => 'View and manage billing only.',
            self::Developer => 'Create and manage environments.',
            self::Viewer => 'Read-only access.',
        };
    }

    /** Invite, remove, and change the role of other members. */
    public function canManageMembers(): bool
    {
        return $this === self::Owner || $this === self::Admin;
    }

    /** See and change the plan / billing. */
    public function canManageBilling(): bool
    {
        return match ($this) {
            self::Owner, self::Admin, self::Billing => true,
            default => false,
        };
    }

    /**
     * Read the member roster (PII). Owners/admins manage it; a read-only Viewer may
     * see it; a Developer (a technical/CI credential) and a Billing-only role may
     * NOT — a leaked developer key must not enumerate the team.
     */
    public function canReadMembers(): bool
    {
        return match ($this) {
            self::Owner, self::Admin, self::Viewer => true,
            default => false,
        };
    }

    /** Read billing/plan/usage. Managers plus the read-only Viewer; not a Developer. */
    public function canReadBilling(): bool
    {
        return $this->canManageBilling() || $this === self::Viewer;
    }

    /** Create environments and manage their settings. */
    public function canManageEnvironments(): bool
    {
        return match ($this) {
            self::Owner, self::Admin, self::Developer => true,
            default => false,
        };
    }

    /**
     * Whether this role may be restricted to a subset of environments. Owners and
     * admins administer the whole account, so they always have every environment;
     * only the scoped roles can be pinned to specific ones (Stripe's prod-vs-test
     * developer access).
     */
    public function supportsEnvironmentScoping(): bool
    {
        return ! ($this === self::Owner || $this === self::Admin);
    }

    /**
     * The same authority, expressed on the organization plane.
     *
     * An account IS an organization in the platform root, so a member's place in it is an
     * ordinary membership — and after the fold the membership is what the console asks.
     * This is the one definition of how the two vocabularies line up, so the mapping
     * cannot be re-derived differently by a caller that needs it.
     *
     * BILLING DOES NOT SURVIVE, and is mapped to Viewer rather than to a new organization
     * role. `MembershipRole` has no billing case, and adding one would be worse than the
     * loss: `canWrite()` is "not a Viewer", so a billing role would arrive holding write
     * access to every organization's resources on every tenant, and correcting that means
     * changing what `canWrite()` means for everyone. Viewer keeps the half of Billing that
     * is reachable — reading the plan — and drops `canManageBilling()`, which no page and
     * no route in the product asks for.
     *
     * Every other case maps to its namesake, and each namesake answers the same way to
     * every predicate the console uses: see `docs/core-concepts/account-and-membership-roles.md`,
     * and the mapping test that pins it.
     */
    public function asMembershipRole(): MembershipRole
    {
        return match ($this) {
            self::Owner => MembershipRole::Owner,
            self::Admin => MembershipRole::Admin,
            self::Developer => MembershipRole::Developer,
            self::Billing, self::Viewer => MembershipRole::Viewer,
        };
    }

    /**
     * Roles a member with a management role may assign. Owner is deliberately
     * excluded — ownership transfer is a separate, deliberate action, never a
     * casual role change.
     *
     * @return list<self>
     */
    public static function assignable(): array
    {
        return [self::Admin, self::Billing, self::Developer, self::Viewer];
    }
}
