<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Enums;

/**
 * A member's coarse role in an organization.
 *
 * This is authorization data — the last-owner protection guard and the console's
 * isOwner/isAdmin checks turn on it — so it is an enum, never a raw string: an
 * invalid role is unrepresentable and a typo is a type error, not a silent
 * fail-open. Mirrors the {@see MembershipStatus} treatment on the same model.
 *
 * Roles are strictly ordered (see {@see self::weight()}) so effective-access
 * resolution can pick a single winner when several sources apply — membership,
 * a project-level grant, a row-level grant, or a group-inherited grant. The
 * generic Member sits between Developer and Viewer: it can write, but carries
 * no technical-plane connotation; hosts that want the four-tier
 * Owner > Admin > Developer > Viewer model simply never assign Member.
 */
enum MembershipRole: string
{
    case Owner = 'owner';
    case Admin = 'admin';
    case Developer = 'developer';
    case Member = 'member';
    case Viewer = 'viewer';

    public function label(): string
    {
        return match ($this) {
            self::Owner => 'Owner',
            self::Admin => 'Admin',
            self::Developer => 'Developer',
            self::Member => 'Member',
            self::Viewer => 'Viewer',
        };
    }

    /**
     * Manage the organization itself: members, invitations, settings,
     * destructive actions. Deliberately limited to Owner/Admin — a Developer
     * is a technical role, not an administrative one.
     */
    public function canManageOrganization(): bool
    {
        return $this === self::Owner || $this === self::Admin;
    }

    /**
     * Mutate resources the organization owns. Everyone but the read-only
     * Viewer.
     */
    public function canWrite(): bool
    {
        return $this !== self::Viewer;
    }

    /**
     * Ordering for effective-access resolution: when several grant sources
     * apply to the same subject, the highest-weighted role wins. Gaps of ten
     * leave room for host-defined intermediate roles without renumbering.
     */
    public function weight(): int
    {
        return match ($this) {
            self::Owner => 50,
            self::Admin => 40,
            self::Developer => 30,
            self::Member => 20,
            self::Viewer => 10,
        };
    }

    public function outranks(self $other): bool
    {
        return $this->weight() > $other->weight();
    }
}
