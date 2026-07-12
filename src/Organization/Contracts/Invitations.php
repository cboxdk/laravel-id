<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\Organization\Exceptions\InvalidInvitation;
use Cbox\Id\Organization\Models\Invitation;
use Cbox\Id\Organization\Models\Membership;
use Cbox\Id\Organization\ValueObjects\PendingInvitation;
use Illuminate\Database\Eloquent\Collection;

/**
 * Organization invitations with explicit acceptance. Creating an invitation does
 * NOT grant membership — that only happens when the invitee accepts via the
 * emailed token. This keeps joining consensual and stops an admin from adding an
 * existing account to their org without the user's action.
 */
interface Invitations
{
    public function invite(string $organizationId, string $email, string $role, ?string $invitedBy = null): PendingInvitation;

    /**
     * Accept an invitation on behalf of a resolved subject: creates the
     * membership and marks the invitation accepted. Throws
     * {@see InvalidInvitation} if the token is
     * unknown, used, revoked, or expired.
     */
    public function accept(string $token, string $subjectId): Membership;

    public function revoke(string $organizationId, string $invitationId): void;

    public function byToken(string $token): ?Invitation;

    /**
     * The pending (not yet accepted/revoked/expired) invitations for an org.
     *
     * @return Collection<int, Invitation>
     */
    public function pending(string $organizationId): Collection;
}
