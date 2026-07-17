<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Enums;

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
