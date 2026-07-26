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
use Cbox\Id\Organization\Models\Membership;
use Cbox\Id\Organization\Models\Organization;
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

    public function add(string $organizationId, string $userId, string $role, ?string $invitedBy = null): Membership
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
            $existing = Membership::query()->where('user_id', $userId)->first();

            if ($existing !== null) {
                return $existing;
            }

            $membership = new Membership;
            $membership->fill([
                'user_id' => $userId,
                // from(): an unknown role is rejected here, not silently persisted.
                'role' => MembershipRole::from($role),
                'status' => MembershipStatus::Active,
                'invited_by' => $invitedBy,
            ]);
            $membership->save();

            // Same transaction as the row write: the outbox event and the membership
            // commit atomically, so a crash can't leave a changed member with no event
            // (which the outbox could never retry) — closing that drift window.
            $this->emitAndAudit($organizationId, $userId, 'organization.member_added', ['role' => $role]);

            return $membership;
        }));
    }

    public function changeRole(string $organizationId, string $userId, string $role): Membership
    {
        return $this->tenant()->runAs(GenericTenant::of($organizationId), fn (): Membership => DB::transaction(function () use ($organizationId, $userId, $role): Membership {
            $membership = Membership::query()->where('user_id', $userId)->firstOrFail();
            $target = MembershipRole::from($role);

            // Demoting the sole owner would orphan the org — never allow it.
            if ($membership->role === MembershipRole::Owner && $target !== MembershipRole::Owner && $this->ownerCount() <= 1) {
                throw LastOwner::make($organizationId);
            }

            $membership->update(['role' => $target]);

            $this->emitAndAudit($organizationId, $userId, 'organization.member_role_changed', ['role' => $role]);

            return $membership;
        }));
    }

    public function remove(string $organizationId, string $userId): void
    {
        $this->tenant()->runAs(GenericTenant::of($organizationId), fn () => DB::transaction(function () use ($organizationId, $userId): void {
            $membership = Membership::query()->where('user_id', $userId)->first();

            if ($membership !== null && $membership->role === MembershipRole::Owner && $this->ownerCount() <= 1) {
                throw LastOwner::make($organizationId);
            }

            Membership::query()->where('user_id', $userId)->delete();

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

            $this->emitAndAudit($organizationId, $userId, 'organization.member_removed', []);
        }));
    }

    /** Owners in the current tenant scope. */
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
    private function ownerCount(): int
    {
        $lockedOwnerIds = Membership::query()
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
            fn (): ?Membership => Membership::query()->where('user_id', $userId)->first(),
        );
    }

    public function forOrganization(string $organizationId): Collection
    {
        return $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): Collection => Membership::query()->orderBy('created_at')->get(),
        );
    }

    public function paginateForOrganization(string $organizationId, int $perPage = 25): LengthAwarePaginator
    {
        return $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): LengthAwarePaginator => Membership::query()->orderBy('created_at')->paginate($perPage),
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
            fn (): Collection => Membership::query()->where('user_id', $userId)->orderBy('created_at')->get(),
        );
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function emitAndAudit(string $organizationId, string $userId, string $action, array $context): void
    {
        $this->events->emit(new DomainEvent($action, ['user_id' => $userId] + $context, $organizationId));

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::System,
            organizationId: $organizationId,
            targetType: 'user',
            targetId: $userId,
            context: $context,
        ));
    }
}
