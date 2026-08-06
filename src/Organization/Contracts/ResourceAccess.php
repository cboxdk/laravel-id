<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\ValueObjects\AccessGrant;
use Cbox\Id\Organization\ValueObjects\GrantSubject;

/**
 * Role grants on resources, and the effective-role query over every grant
 * source. Resources are host-defined {@see ResourceRef}s — the package does
 * not know what a "project" or a "service" is; the host names its own
 * taxonomy and scoping (a project-wide grant is simply a grant on the
 * project's own ref).
 */
interface ResourceAccess
{
    public function grant(string $organizationId, GrantSubject $subject, MembershipRole $role, ResourceRef $resource): void;

    public function revoke(string $organizationId, GrantSubject $subject, MembershipRole $role, ResourceRef $resource): void;

    /**
     * Every grant on a resource, for admin listings.
     *
     * @return list<AccessGrant>
     */
    public function grantsOn(string $organizationId, ResourceRef $resource): array;

    /**
     * The user's effective role: the highest-weighted role across their
     * active organization membership and every grant matching the given
     * resources — held directly or through any group they belong to. With no
     * resources given, this is the org-level role (membership only). Null
     * means no access at all (deny-by-default).
     */
    public function effectiveRole(string $organizationId, string $userId, ResourceRef ...$resources): ?MembershipRole;
}
