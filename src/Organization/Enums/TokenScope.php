<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Enums;

/**
 * The coarse verb a user API token may perform. Deliberately three-valued —
 * fine-grained restriction is the token's resource-family list, not more
 * verbs. Admin covers organization management (members, settings, tokens).
 */
enum TokenScope: string
{
    case Read = 'read';
    case Write = 'write';
    case Admin = 'admin';

    public function allowsWrite(): bool
    {
        return $this !== self::Read;
    }

    /**
     * A token must never out-rank the member minting it: the scope is capped
     * at the issuer's effective role. Admin scope needs an org-managing role;
     * write scope needs a writing role; read is open to any member.
     */
    public function issuableBy(MembershipRole $role): bool
    {
        return match ($this) {
            self::Admin => $role->canManageOrganization(),
            self::Write => $role->canWrite(),
            self::Read => true,
        };
    }
}
