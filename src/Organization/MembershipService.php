<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Exceptions\ExternalRbacNotBound;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesTenant;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Exceptions\CrossEnvironmentAccess;
use Cbox\Id\Kernel\Tenancy\GenericTenant;
use Cbox\Id\Kernel\Tenancy\Scopes\EnvironmentScope;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Cbox\Id\Organization\Exceptions\LastOwner;
use Cbox\Id\Organization\Exceptions\OwnershipTransferRefused;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\Models\Membership;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Platform\Models\Project;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;

/**
 * Membership operations run inside the target org's tenant scope, so the tenant
 * kernel auto-fills `organization_id` and guarantees reads/writes never cross
 * into another org — the service dogfoods the isolation kernel.
 */
class MembershipService implements Memberships
{
    // Lazy per-call resolution of the ambient tenant. This class is a `singleton`
    // (OrganizationServiceProvider) and TenantContext is `scoped`: injected, every runAs()
    // would set and restore on the first job's manager, scoping nothing.
    use ResolvesTenant;

    public function __construct(
        private readonly EventBus $events,
        private readonly AuditLog $audit,
        private readonly Roles $roles,
    ) {}

    public function add(string $organizationId, string $userId, MembershipRole $role, ?string $invitedBy = null): Membership
    {
        // The organization MUST resolve inside the ambient environment before we write.
        //
        // `runAs()` below sets only the TENANT dimension — it never touches the
        // environment — so without this an organization id from another environment is
        // taken on trust: `BelongsToEnvironment` auto-fills `environment_id` from the
        // ambient context on a fresh INSERT (the CrossEnvironmentAccess guard fires on a
        // MISMATCH, never on an insert), producing a membership whose organization lives
        // in one environment and whose row lives in another. There is also no foreign key
        // on `memberships.organization_id` to catch it at the database layer.
        //
        // Deliberately scoped to the CROSS-ENVIRONMENT case rather than to existence.
        // A host may legitimately drive this primitive with an organization id it manages
        // itself and has never materialised as a row, so "unknown id" stays allowed; what
        // must never be allowed is an id that demonstrably belongs to ANOTHER environment.
        // Hence the unscoped read — it is the only way to see the row we are defending
        // against — with the environment predicate then stated explicitly, as every other
        // `withoutGlobalScope` site in this package does.
        // ...EXCEPT under an explicit `EnvironmentContext::withoutScope()`, which is what
        // every other environment gate does — EnvironmentScope::apply() and
        // BelongsToEnvironment::bootBelongsToEnvironment() both check this first. A
        // suspension is a deliberate, in-process declaration that this code is running as
        // the platform rather than inside a tenant, and it is the mechanism provisioning
        // and backfill commands use; refusing it here would make this one primitive
        // unusable from exactly those callers, for no gain — there is no ambient
        // environment to cross INTO.
        $environments = app(EnvironmentContext::class);

        if (! $environments->isScopingSuspended()) {
            $owner = Organization::query()
                ->withoutGlobalScope(EnvironmentScope::class)
                ->whereKey($organizationId)
                ->first();

            $current = $environments->current()?->environmentKey();

            if ($owner !== null && $owner->environment_id !== $current) {
                throw CrossEnvironmentAccess::forWrite(
                    Membership::class,
                    $owner->environment_id,
                    $current ?? 'none',
                );
            }
        }

        return $this->tenant()->runAs(GenericTenant::of($organizationId), fn (): Membership => DB::transaction(function () use ($organizationId, $userId, $role, $invitedBy): Membership {
            $existing = Membership::query()->where('organization_id', $organizationId)->where('user_id', $userId)->first();

            if ($existing !== null) {
                return $existing;
            }

            $membership = new Membership;
            $membership->fill([
                // Stated, not left to the tenant hook: that hook stands down while scoping
                // is suspended, and the insert then had no organization at all.
                'organization_id' => $organizationId,
                'user_id' => $userId,
                'role' => $role,
                'status' => MembershipStatus::Active,
                'invited_by' => $invitedBy,
            ]);
            $membership->save();

            // Same transaction as the row write: the outbox event and the membership
            // commit atomically, so a crash can't leave a changed member with no event
            // (which the outbox could never retry) — closing that drift window.
            //
            // The audit context records the SAME enum-backed value that was persisted.
            // While this took a raw string it recorded the caller's spelling, so a
            // case-variant input made the audit trail disagree with the stored role.
            $this->emitAndAudit($organizationId, $userId, 'organization.member_added', ['role' => $role->value]);

            $this->announce('membership.created', $organizationId, $userId, [
                'role' => $role->value,
                'status' => MembershipStatus::Active->value,
                'invited_by' => $invitedBy,
            ]);

            return $membership;
        }));
    }

    public function changeRole(string $organizationId, string $userId, MembershipRole $role): Membership
    {
        return $this->tenant()->runAs(GenericTenant::of($organizationId), fn (): Membership => DB::transaction(function () use ($organizationId, $userId, $role): Membership {
            $membership = Membership::query()->where('organization_id', $organizationId)->where('user_id', $userId)->firstOrFail();

            // Demoting the sole owner would orphan the org — never allow it.
            if ($membership->role === MembershipRole::Owner && $role !== MembershipRole::Owner && $this->ownerCount($organizationId) <= 1) {
                throw LastOwner::make($organizationId);
            }

            $previous = $membership->role;

            $membership->update(['role' => $role]);

            $this->emitAndAudit($organizationId, $userId, 'organization.member_role_changed', ['role' => $role->value]);

            // Only for a change that happened. The legacy event above has always fired on
            // a no-op too, and consumers built on it keep that; the new one says "updated"
            // and a write that changed nothing is not an update.
            if ($previous !== $role) {
                $this->announce('membership.updated', $organizationId, $userId, [
                    'role' => $role->value,
                    'previous_role' => $previous->value,
                    'reason' => 'role_changed',
                ]);
            }

            return $membership;
        }));
    }

    public function remove(string $organizationId, string $userId): void
    {
        $this->tenant()->runAs(GenericTenant::of($organizationId), fn () => DB::transaction(function () use ($organizationId, $userId): void {
            $membership = Membership::query()
                ->where('organization_id', $organizationId)
                ->where('user_id', $userId)
                ->lockForUpdate()
                ->first();

            if ($membership !== null && $membership->role === MembershipRole::Owner && $this->ownerCount($organizationId) <= 1) {
                throw LastOwner::make($organizationId);
            }

            $this->detach($organizationId, $userId, $membership, 'removed');
        }));
    }

    public function leave(string $organizationId, string $userId): void
    {
        $this->tenant()->runAs(GenericTenant::of($organizationId), fn () => DB::transaction(function () use ($organizationId, $userId): void {
            $membership = Membership::query()
                ->where('organization_id', $organizationId)
                ->where('user_id', $userId)
                ->lockForUpdate()
                ->first();

            // Idempotent. Leaving somewhere you are not is already done, and answering a
            // retried request with an error would tell the person their leave failed.
            if ($membership === null) {
                return;
            }

            // The same locked count remove() uses, so an owner leaving at the same moment
            // as the only other owner cannot both succeed. The refusal is the LEAVING one:
            // it tells the person what to do instead, not just which invariant held.
            if ($membership->role === MembershipRole::Owner && $this->ownerCount($organizationId) <= 1) {
                throw LastOwner::leaving($organizationId);
            }

            $this->detach($organizationId, $userId, $membership, 'left');
        }));
    }

    public function transferOwnership(string $organizationId, string $fromUserId, string $toUserId): Membership
    {
        if ($fromUserId === $toUserId) {
            throw OwnershipTransferRefused::sameMember($organizationId);
        }

        return $this->tenant()->runAs(GenericTenant::of($organizationId), fn (): Membership => DB::transaction(function () use ($organizationId, $fromUserId, $toUserId): Membership {
            // BOTH rows locked, in one statement ordered by primary key. The lock is what
            // makes the transfer atomic against the other lifecycle verbs: a concurrent
            // remove()/leave() of either person, a changeRole() demoting the owner, or a
            // second transfer out of the same owner all wait here and then re-read the
            // state this one left. Ordering by id means two transfers crossing between the
            // same pair take the locks in the same order and cannot deadlock.
            //
            // The organization is bound in the WHERE clause as well as by the tenant scope,
            // so a suspended scope cannot turn a member of ANOTHER organization into a
            // match — and so into that organization's owner.
            $rows = Membership::query()
                ->where('organization_id', $organizationId)
                ->whereIn('user_id', [$fromUserId, $toUserId])
                ->orderBy('id')
                ->lockForUpdate()
                ->get();

            $from = $rows->firstWhere('user_id', $fromUserId);
            $to = $rows->firstWhere('user_id', $toUserId);

            if (! $from instanceof Membership
                || $from->role !== MembershipRole::Owner
                || $from->status !== MembershipStatus::Active) {
                throw OwnershipTransferRefused::notOwner($organizationId, $fromUserId);
            }

            if (! $to instanceof Membership) {
                throw OwnershipTransferRefused::targetNotMember($organizationId, $toUserId);
            }

            if ($to->status !== MembershipStatus::Active) {
                throw OwnershipTransferRefused::targetNotActive($organizationId, $toUserId);
            }

            $toPrevious = $to->role;

            // Promote first, then demote: at no point inside the transaction does the
            // organization have fewer owners than it started with.
            $to->update(['role' => MembershipRole::Owner]);
            $from->update(['role' => MembershipRole::Admin]);

            // The legacy per-member event for each side, because provisioning and usage
            // metering key off it — a transfer IS two role changes to them.
            $this->emitAndAudit($organizationId, $toUserId, 'organization.member_role_changed', ['role' => MembershipRole::Owner->value]);
            $this->emitAndAudit($organizationId, $fromUserId, 'organization.member_role_changed', ['role' => MembershipRole::Admin->value]);

            $this->announce('membership.updated', $organizationId, $toUserId, [
                'role' => MembershipRole::Owner->value,
                'previous_role' => $toPrevious->value,
                'reason' => 'ownership_transferred',
            ]);
            $this->announce('membership.updated', $organizationId, $fromUserId, [
                'role' => MembershipRole::Admin->value,
                'previous_role' => MembershipRole::Owner->value,
                'reason' => 'ownership_transferred',
            ]);

            // One entry that names both sides, attributed to the owner who handed it over —
            // the two role-change entries above say what happened to each row, this one
            // says why.
            $this->audit->record(new AuditEvent(
                action: 'organization.ownership_transferred',
                actorType: ActorType::User,
                actorId: $fromUserId,
                organizationId: $organizationId,
                targetType: 'user',
                targetId: $toUserId,
                context: ['from_user_id' => $fromUserId, 'to_user_id' => $toUserId],
            ));

            return $to;
        }));
    }

    public function owners(string $organizationId): array
    {
        /** @var list<string> */
        return $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): array => Membership::query()
                ->where('organization_id', $organizationId)
                ->where('role', MembershipRole::Owner->value)
                ->where('status', MembershipStatus::Active->value)
                ->orderBy('id')
                ->pluck('user_id')
                ->map(static fn (mixed $id): string => is_scalar($id) ? (string) $id : '')
                ->filter(static fn (string $id): bool => $id !== '')
                ->values()
                ->all(),
        );
    }

    public function activeRole(string $organizationId, string $userId): ?MembershipRole
    {
        // Everything the answer depends on is in the WHERE clause — organization included,
        // so a caller running with tenant scoping suspended still gets THIS organization's
        // tier and never another one's. It becomes a claim a relying party authorizes on.
        $membership = $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): ?Membership => Membership::query()
                ->where('organization_id', $organizationId)
                ->where('user_id', $userId)
                ->where('status', MembershipStatus::Active->value)
                ->first(),
        );

        return $membership?->role;
    }

    /**
     * Delete a membership and everything that hangs off it, inside the caller's
     * transaction and tenant scope. `$membership` is the row as locked by the caller (or
     * null when there was none); `$reason` says which verb it was, for the webhook.
     */
    private function detach(string $organizationId, string $userId, ?Membership $membership, string $reason): void
    {
        // Organization bound here too, not only by the tenant scope: under a suspended
        // scope a bare `where user_id` deletes the person from every organization.
        Membership::query()->where('organization_id', $organizationId)->where('user_id', $userId)->delete();

        // Drop the RBAC grants with the membership. Assignments are read by
        // (organization, user) with no membership join, so leaving them behind is not
        // untidiness: re-adding the person later silently restores privileges nobody
        // re-granted, and anything reading assignments directly still sees them held.
        //
        // A deployment that binds EXTERNAL RBAC owns its own grants and has none here
        // to revoke — that refusal is the contract working, not a failure to remove a
        // member, so it does not abort the removal.
        try {
            $this->roles->unassignAll($organizationId, $userId);
        } catch (ExternalRbacNotBound) {
            // Nothing of ours to revoke.
        }

        $this->emitAndAudit(
            $organizationId,
            $userId,
            'organization.member_removed',
            $reason === 'left' ? ['reason' => 'left'] : [],
            $reason === 'left' ? ActorType::User : ActorType::System,
            $reason === 'left' ? $userId : null,
        );

        // The legacy event above has always fired even when there was no row to delete;
        // the new one reports a membership that existed, with the role it had.
        if ($membership !== null) {
            $this->announce('membership.deleted', $organizationId, $userId, [
                'role' => $membership->role->value,
                'reason' => $reason,
            ]);
        }
    }

    /**
     * How many owners this organization has, with the owner rows LOCKED for the rest of
     * the transaction.
     *
     * The lock is the point. Two owners each demoting (or removing) themselves at the
     * same moment would both read a count of 2, both conclude they are not the last one,
     * and both commit — leaving an organization with no owner and no way to appoint one.
     * Locking the rows serializes the two transactions, so the second re-reads a count of
     * 1 and is correctly refused.
     *
     * The rows are fetched and counted in PHP rather than with `count()`, because
     * PostgreSQL rejects `FOR UPDATE` alongside an aggregate.
     */
    private function ownerCount(string $organizationId): int
    {
        // Organization bound in the WHERE clause, not left to the tenant scope: under a
        // suspended scope an unbound count is every owner of every organization, and the
        // last-owner guard could never fire.
        $lockedOwnerIds = Membership::query()
            ->where('organization_id', $organizationId)
            ->where('role', MembershipRole::Owner->value)
            ->lockForUpdate()
            ->pluck('id')
            ->all();

        return count($lockedOwnerIds);
    }

    public function of(string $organizationId, string $userId): ?Membership
    {
        return $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): ?Membership => Membership::query()->where('organization_id', $organizationId)->where('user_id', $userId)->first(),
        );
    }

    /**
     * Oldest-first, and TOTALLY ordered.
     *
     * `created_at` is a second-granularity timestamp, so a roster built in one request
     * — an import, a seeder, the tests — ties on every row. `ORDER BY` a tied key is
     * not a sort SQL promises anything about: PostgreSQL returns whatever the plan
     * happens to produce, and for the paginated call below that is a top-N heapsort,
     * which is not stable. The visible symptom was page 1 of a five-member roster
     * starting at the second member.
     *
     * Under LIMIT/OFFSET this is worse than cosmetic: a non-unique sort key lets a row
     * appear on two pages, or on none. `id` is a ULID — monotonic by creation — so it
     * breaks the tie in the same direction `created_at` intends, and makes the order
     * total.
     */
    public function forOrganization(string $organizationId): Collection
    {
        return $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): Collection => Membership::query()->orderBy('created_at')->orderBy('id')->get(),
        );
    }

    public function userIdsForOrganization(string $organizationId): array
    {
        /** @var list<string> */
        return $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): array => Membership::query()
                ->pluck('user_id')
                ->map(static fn (mixed $id): string => is_scalar($id) ? (string) $id : '')
                ->filter(static fn (string $id): bool => $id !== '')
                ->values()
                ->all(),
        );
    }

    public function paginateForOrganization(string $organizationId, int $perPage = 25): LengthAwarePaginator
    {
        return $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): LengthAwarePaginator => Membership::query()
                ->orderBy('created_at')
                ->orderBy('id')
                ->paginate($perPage),
        );
    }

    public function countForOrganization(string $organizationId): int
    {
        return $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): int => Membership::query()->count(),
        );
    }

    public function forUser(string $userId): Collection
    {
        // Cross-tenant by nature — a subject's own list of organizations.
        return $this->tenant()->withoutScope(
            // Same total order as forOrganization() — see the note there.
            fn (): Collection => Membership::query()
                ->where('user_id', $userId)
                ->orderBy('created_at')
                ->orderBy('id')
                ->get(),
        );
    }

    /**
     * Restrict a membership to a SUBSET of the environments its organization owns.
     *
     * The two halves are kept from ever disagreeing: lifting the restriction detaches
     * every grant, so there is never a boolean saying "everything" beside rows saying
     * "these three" — a question with two answers, which the readers would have to pick
     * between and would pick differently.
     *
     * THE FILTER IS THE SECURITY CONTROL, not tidiness. The gates ask "is the host
     * environment in this member's list", so an id in that list IS access — a grant naming
     * another organization's environment would not be a stray row, it would be a way in.
     * So the ids are intersected with what this organization actually owns before anything
     * is written, and the caller's list is never trusted to have been checked already.
     *
     * A membership that does not exist is a no-op rather than an error: the caller has
     * already been told who the member is by the console it rendered, and inventing a
     * restriction for somebody who is not there writes a row nothing will ever read.
     *
     * @param  list<string>  $environmentIds
     */
    public function setEnvironmentAccess(string $organizationId, string $userId, bool $all, array $environmentIds = []): void
    {
        $membership = $this->of($organizationId, $userId);

        if ($membership === null) {
            return;
        }

        $membership->all_environments = $all;
        $membership->save();

        if ($all) {
            $membership->environments()->detach();

            return;
        }

        $membership->environments()->sync(
            array_values(array_intersect($this->ownedEnvironmentIds($organizationId), $environmentIds)),
        );
    }

    /**
     * @return list<string>
     */
    public function accessibleEnvironmentIds(string $organizationId, string $userId): array
    {
        $membership = $this->of($organizationId, $userId);

        // No membership, no access. Answered with the empty list rather than null so a
        // caller cannot read "unknown" as "unrestricted" — every reader of this is an
        // authorization gate, and the two must not be the same value.
        if ($membership === null) {
            return [];
        }

        if ($membership->all_environments) {
            return $this->ownedEnvironmentIds($organizationId);
        }

        // Intersected with current ownership on READ as well as on write. A grant survives
        // an environment moving to another organization, and the row alone would then
        // still say yes; ownership is the fact, the grant only narrows it.
        $granted = [];

        foreach ($membership->environments()->pluck('environments.id') as $id) {
            if (is_string($id) && $id !== '') {
                $granted[] = $id;
            }
        }

        return array_values(array_intersect($this->ownedEnvironmentIds($organizationId), $granted));
    }

    public function accessibleEnvironmentIdsFor(string $organizationId, array $userIds): array
    {
        if ($userIds === []) {
            return [];
        }

        // Owned once for the whole page rather than once per member: it is a property of
        // the ORGANIZATION, and asking it per row is most of what made this expensive.
        $owned = $this->ownedEnvironmentIds($organizationId);

        // INSIDE THE TENANT, like every other membership read in this class. `Membership`
        // is `TenantOwned` and the scope is deny-by-default, so a bare query filtered by
        // `organization_id` returns nothing at all — silently, and in the safe direction,
        // which is exactly what makes it easy to write and hard to notice.
        $memberships = $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): Collection => Membership::query()
                ->whereIn('user_id', $userIds)
                ->with('environments:id')
                ->get(),
        );

        $access = [];

        foreach ($memberships as $membership) {
            if ($membership->all_environments) {
                $access[$membership->user_id] = $owned;

                continue;
            }

            // Intersected with current ownership on READ as well as on write, exactly as
            // the single-member call does: a grant survives an environment moving to
            // another organization, and the row alone would then still say yes.
            $granted = [];

            foreach ($membership->environments as $environment) {
                if ($environment->id !== '') {
                    $granted[] = $environment->id;
                }
            }

            $access[$membership->user_id] = array_values(array_intersect($owned, $granted));
        }

        return $access;
    }

    /**
     * Every environment this organization owns, through the projects it owns.
     *
     * `environments.account_id` is not consulted. An account IS an organization, so the
     * account-keyed answer is a subset of this one at best, and it disappears entirely
     * when the account plane is folded away — reading it here would be writing the new
     * home in terms of the old one.
     *
     * @return list<string>
     */
    private function ownedEnvironmentIds(string $organizationId): array
    {
        $ids = Environment::query()
            ->whereIn('project_id', Project::query()->where('organization_id', $organizationId)->select('id'))
            ->orderBy('id')
            ->pluck('id')
            ->all();

        $out = [];

        foreach ($ids as $id) {
            if (is_string($id) && $id !== '') {
                $out[] = $id;
            }
        }

        return $out;
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function emitAndAudit(
        string $organizationId,
        string $userId,
        string $action,
        array $context,
        ActorType $actorType = ActorType::System,
        ?string $actorId = null,
    ): void {
        $this->events->emit(new DomainEvent($action, ['user_id' => $userId] + $context, $organizationId));

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: $actorType,
            actorId: $actorId,
            organizationId: $organizationId,
            targetType: 'user',
            targetId: $userId,
            context: $context,
        ));
    }

    /**
     * Emit one of the `membership.*` webhook events.
     *
     * Beside the legacy `organization.member_*` events rather than instead of them:
     * outbound provisioning and usage metering key off the legacy names, and so may any
     * webhook endpoint that subscribed to them by name. The new events carry what the old
     * ones never did — the previous role, and why the change happened — in one shape
     * across all three.
     *
     * @param  array<string, mixed>  $payload
     */
    private function announce(string $type, string $organizationId, string $userId, array $payload): void
    {
        $this->events->emit(new DomainEvent(
            $type,
            ['organization_id' => $organizationId, 'user_id' => $userId] + $payload,
            $organizationId,
        ));
    }
}
