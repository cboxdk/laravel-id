<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\Organization\Models\Membership;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;

interface Memberships
{
    public function add(string $organizationId, string $userId, string $role, ?string $invitedBy = null): Membership;

    public function changeRole(string $organizationId, string $userId, string $role): Membership;

    public function remove(string $organizationId, string $userId): void;

    public function of(string $organizationId, string $userId): ?Membership;

    /**
     * Every membership in an organization (the org's member list).
     *
     * @return Collection<int, Membership>
     */
    public function forOrganization(string $organizationId): Collection;

    /**
     * A single page of an organization's memberships, ordered oldest-first, for admin
     * consoles that must not hydrate an unbounded roster into one request.
     *
     * @return LengthAwarePaginator<int, Membership>
     */
    public function paginateForOrganization(string $organizationId, int $perPage = 25): LengthAwarePaginator;

    /**
     * Every organization a subject belongs to — a legitimate cross-tenant
     * "which orgs am I in" lookup.
     *
     * @return Collection<int, Membership>
     */
    public function forUser(string $userId): Collection;
}
