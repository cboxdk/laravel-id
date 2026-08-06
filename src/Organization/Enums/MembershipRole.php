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
     * Read the member roster, which is PII.
     *
     * NOT the same question as {@see canWrite()}, and deliberately excludes the two
     * technical roles. A Developer is frequently a CI or agent credential rather than a
     * person, and a leaked one must not be able to enumerate the team; the generic Member
     * is a collaborator on the organization's resources, not an administrator of its
     * people. The read-only Viewer may look precisely because it can do nothing else.
     */
    public function canReadMembers(): bool
    {
        return match ($this) {
            self::Owner, self::Admin, self::Viewer => true,
            default => false,
        };
    }

    /**
     * Read the plan, invoices and usage.
     *
     * The same set as {@see canReadMembers()} today, and separate from it on purpose:
     * they are different questions, they are asked by different pages, and a host that
     * introduces a finance role will want to move one without the other.
     */
    public function canReadBilling(): bool
    {
        return match ($this) {
            self::Owner, self::Admin, self::Viewer => true,
            default => false,
        };
    }

    /**
     * Create and administer the IdP products this organization owns — its projects,
     * their environments, and the keys and domains those need.
     *
     * NOT {@see canWrite()}, and the difference is the whole reason this exists. `canWrite`
     * admits the generic Member, which is the role every person placed in an organization
     * carries by default; standing up an environment is an administrative act on the
     * product the organization sells, and it grants a live environment-admin session on
     * that tenant's own host. Collapsing the two would hand that to everybody who was
     * merely added to the organization.
     */
    public function canManageEnvironments(): bool
    {
        return match ($this) {
            self::Owner, self::Admin, self::Developer => true,
            default => false,
        };
    }

    /**
     * Whether this role may be restricted to a subset of the organization's environments.
     *
     * Owners and admins administer the whole organization, so they always have every one;
     * only the scoped roles can be pinned. Stated as "not an administrator" rather than as
     * a list of the scopable roles, so a role added later is scopable by default — the
     * safe direction.
     */
    public function supportsEnvironmentScoping(): bool
    {
        return ! $this->canManageOrganization();
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

    /**
     * The roles a console or API may HAND OUT — inviting a colleague, stamping a machine
     * credential, changing somebody's role.
     *
     * `Owner` is absent and that is the point: ownership is TRANSFERRED, never assigned.
     * An organization has exactly one, {@see Contracts\Memberships} refuses to demote or
     * remove the last one, and an "assign owner" control would be a second way to reach a
     * state the transfer verb exists to keep coherent.
     *
     * The account plane had this method and its list was `[Admin, Developer, Viewer]` —
     * narrower because that vocabulary carried a `Billing` case that could not be honoured
     * faithfully and was withdrawn from the picker rather than mapped loosely. This
     * vocabulary has no such case, so `Member` is offerable: it is the ordinary role, the
     * one an invited colleague should usually get, and omitting it would push every
     * invitation up to Developer.
     *
     * @return list<self>
     */
    public static function assignable(): array
    {
        return [self::Admin, self::Developer, self::Member, self::Viewer];
    }
}
