<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\PrivilegedSubjects;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\MembershipStatus;

/**
 * The default {@see PrivilegedSubjects}: an owner or admin of any organization they are an
 * ACTIVE member of — the roles that can manage members, invitations and settings
 * ({@see MembershipRole::canManageOrganization()}). A suspended membership confers
 * nothing.
 */
class MembershipPrivilegedSubjects implements PrivilegedSubjects
{
    public function __construct(private readonly Memberships $memberships) {}

    public function isPrivileged(string $subjectId): bool
    {
        foreach ($this->memberships->forUser($subjectId) as $membership) {
            if ($membership->status === MembershipStatus::Active
                && $membership->role->canManageOrganization()) {
                return true;
            }
        }

        return false;
    }
}
