<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Models\Membership;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;

interface Memberships
{
    /**
     * The role is a {@see MembershipRole}, never a raw string. This is authorization
     * data — the last-owner guard and the console's isOwner/isAdmin checks turn on it —
     * so an invalid role must be unrepresentable at the boundary rather than an
     * uncaught `ValueError` deep inside a transaction. Parse an untrusted string at
     * the HTTP edge (`MembershipRole::tryFrom()`), where a bad value is a validation
     * failure the caller can act on.
     */
    public function add(string $organizationId, string $userId, MembershipRole $role, ?string $invitedBy = null): Membership;

    public function changeRole(string $organizationId, string $userId, MembershipRole $role): Membership;

    public function remove(string $organizationId, string $userId): void;

    public function of(string $organizationId, string $userId): ?Membership;

    /**
     * Every membership in an organization (the org's member list).
     *
     * @return Collection<int, Membership>
     */
    public function forOrganization(string $organizationId): Collection;

    /**
     * Just the subject ids in an organization, for a caller that only wants to FILTER by
     * them.
     *
     * Hydrating every membership to reduce it to `->pluck('user_id')` is one model per
     * person for a list that is thrown away — and the callers doing it are pages that ask
     * twice per render. This reads one column and nothing else.
     *
     * Still every member, because that is what a filter needs: bounding this would silently
     * hide rows rather than paginate them. A caller whose own list is paginated should
     * narrow to its page's ids instead of calling this.
     *
     * @return list<string>
     */
    public function userIdsForOrganization(string $organizationId): array;

    /**
     * A single page of an organization's memberships, ordered oldest-first, for admin
     * consoles that must not hydrate an unbounded roster into one request.
     *
     * @return LengthAwarePaginator<int, Membership>
     */
    public function paginateForOrganization(string $organizationId, int $perPage = 25): LengthAwarePaginator;

    /**
     * Count an organization's memberships without hydrating them — for admin surfaces
     * (dashboard tiles) that need only the number, not the roster. Avoids loading every
     * membership model into memory just to call count() on the collection.
     */
    public function countForOrganization(string $organizationId): int;

    /**
     * Every organization a subject belongs to — a legitimate cross-tenant
     * "which orgs am I in" lookup.
     *
     * @return Collection<int, Membership>
     */
    public function forUser(string $userId): Collection;

    /**
     * Restrict a membership to a SUBSET of the environments its organization owns, or
     * lift the restriction.
     *
     * `$all = true` is the unrestricted state and detaches every grant, so the two halves
     * can never disagree — a boolean saying "everything" beside rows saying "these three"
     * is a question with two answers, and the readers would have to pick one.
     *
     * `$environmentIds` is filtered against what the organization actually owns before
     * anything is written. A grant naming somebody else's environment must not be
     * storable: the gates ask "is the host environment in this member's list", so a
     * foreign id in the list is not a stray row, it is access.
     *
     * @param  list<string>  $environmentIds  ignored when `$all` is true
     */
    public function setEnvironmentAccess(string $organizationId, string $userId, bool $all, array $environmentIds = []): void;

    /**
     * Every environment this membership may reach — the whole set its organization owns
     * when unrestricted, the granted subset otherwise.
     *
     * This is what an authorization gate asks, so it answers with ids rather than models
     * and never with null: an empty list is "nothing", which is the safe reading, and a
     * membership that does not exist gets exactly that.
     *
     * @return list<string>
     */
    public function accessibleEnvironmentIds(string $organizationId, string $userId): array;

    /**
     * The same answer for a page of members at once, keyed by user id.
     *
     * WHY A BATCH EXISTS AT ALL. The console draws this per row — "3 of 8 environments" —
     * and the single-member call is three queries: the membership, the grants, and what
     * the organization owns. A roster rendered a row at a time therefore cost three
     * queries per person on top of the person themselves, which measured at 10 queries per
     * member and 1037 on a 101-member page. `Subjects::findMany()` exists for the same
     * reason and this is its other half.
     *
     * A user id with no membership in this organization is absent from the result rather
     * than present with an empty list — the caller reads a missing key the same way, and
     * inventing a row for somebody who is not a member would be inventing an answer.
     *
     * @param  list<string>  $userIds
     * @return array<string, list<string>>
     */
    public function accessibleEnvironmentIdsFor(string $organizationId, array $userIds): array;
}
