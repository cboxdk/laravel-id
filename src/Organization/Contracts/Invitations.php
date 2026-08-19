<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\Organization\Enums\MembershipRole;
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
    /**
     * The role the invitee will hold once they accept — a {@see MembershipRole}, never
     * a raw string, for the same reason {@see Memberships::add()} takes one: it is the
     * authorization level the resulting membership is created with.
     */
    public function invite(string $organizationId, string $email, MembershipRole $role, ?string $invitedBy = null): PendingInvitation;

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
     * @param  int|null  $limit  the newest N, or all of them when null. A console listing
     *                           them wants a bounded read; a caller acting on every one
     *                           of them wants all — the two must be able to say which.
     * @return Collection<int, Invitation>
     */
    public function pending(string $organizationId, ?int $limit = null): Collection;

    /** How many pending invitations the org has, without reading them. */
    public function countPending(string $organizationId): int;
}
