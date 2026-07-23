<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Authorization\Contracts\RelationshipStore;
use Cbox\Id\Kernel\Authorization\Models\RelationshipTuple;
use Cbox\Id\Kernel\Authorization\ValueObjects\Relationship;
use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\GenericTenant;
use Cbox\Id\Organization\Contracts\ResourceAccess;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Cbox\Id\Organization\Models\Membership;
use Cbox\Id\Organization\Models\UserGroup;
use Cbox\Id\Organization\ValueObjects\AccessGrant;
use Cbox\Id\Organization\ValueObjects\GrantSubject;
use Illuminate\Database\Eloquent\Builder;

/**
 * Grants are relationship tuples — object is the resource, relation is the
 * role value, subject is the user (direct) or the group's members userset. So
 * the boolean PDP path answers "does this user hold role R on this resource"
 * with group expansion for free, and this service adds the ordered query on
 * top: the single highest-weighted role across membership + matching grants.
 */
class ResourceAccessService implements ResourceAccess
{
    public function __construct(
        private readonly TenantContext $tenant,
        private readonly RelationshipStore $relationships,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function grant(string $organizationId, GrantSubject $subject, MembershipRole $role, ResourceRef $resource): void
    {
        // A grant to a nonexistent group would silently confer access to
        // whoever later gets that id — refuse it up front.
        if ($subject->isGroup()) {
            $this->tenant->runAs(
                GenericTenant::of($organizationId),
                fn () => UserGroup::query()->whereKey($subject->id)->firstOrFail(),
            );
        }

        $this->relationships->write($this->tuple($organizationId, $subject, $role, $resource));

        $this->emitAndAudit($organizationId, 'organization.access_granted', $subject, $role, $resource);
    }

    public function revoke(string $organizationId, GrantSubject $subject, MembershipRole $role, ResourceRef $resource): void
    {
        $this->relationships->delete($this->tuple($organizationId, $subject, $role, $resource));

        $this->emitAndAudit($organizationId, 'organization.access_revoked', $subject, $role, $resource);
    }

    public function grantsOn(string $organizationId, ResourceRef $resource): array
    {
        return $this->tenant->runAs(GenericTenant::of($organizationId), function () use ($resource): array {
            $grants = [];

            $tuples = RelationshipTuple::query()
                ->where('object_type', $resource->type)
                ->where('object_id', $resource->id)
                ->whereIn('relation', self::roleValues())
                ->orderBy('subject_type')
                ->orderBy('subject_id')
                ->get();

            foreach ($tuples as $tuple) {
                $subject = $tuple->subject_type === GroupService::OBJECT_TYPE
                    ? GrantSubject::group($tuple->subject_id)
                    : GrantSubject::user($tuple->subject_id);

                $grants[] = new AccessGrant(
                    subject: $subject,
                    role: MembershipRole::from($tuple->relation),
                    resource: $resource,
                );
            }

            return $grants;
        });
    }

    public function effectiveRole(string $organizationId, string $userId, ResourceRef ...$resources): ?MembershipRole
    {
        return $this->tenant->runAs(GenericTenant::of($organizationId), function () use ($userId, $resources): ?MembershipRole {
            $candidates = [];

            // Source 1: active org membership. Suspended members keep their
            // row but lose their access.
            $membership = Membership::query()
                ->where('user_id', $userId)
                ->where('status', MembershipStatus::Active->value)
                ->first();

            if ($membership !== null) {
                $candidates[] = $membership->role;
            }

            // Source 2: grants on the given resources — direct, or through
            // any group the user belongs to.
            if ($resources !== []) {
                foreach ($this->matchingGrantRoles($userId, array_values($resources)) as $role) {
                    $candidates[] = $role;
                }
            }

            return $this->highest($candidates);
        });
    }

    /**
     * Resolve the user's groups once, then fetch every matching grant in a
     * single query. Runs inside the caller's tenant scope.
     *
     * @param  list<ResourceRef>  $resources
     * @return list<MembershipRole>
     */
    private function matchingGrantRoles(string $userId, array $resources): array
    {
        $groupIds = RelationshipTuple::query()
            ->where('object_type', GroupService::OBJECT_TYPE)
            ->where('relation', GroupService::MEMBER_RELATION)
            ->where('subject_type', 'user')
            ->where('subject_id', $userId)
            ->whereNull('subject_relation')
            ->pluck('object_id')
            ->all();

        $relations = RelationshipTuple::query()
            ->where(function (Builder $query) use ($resources): void {
                foreach ($resources as $resource) {
                    $query->orWhere(function (Builder $query) use ($resource): void {
                        $query->where('object_type', $resource->type)
                            ->where('object_id', $resource->id);
                    });
                }
            })
            ->whereIn('relation', self::roleValues())
            ->where(function (Builder $query) use ($userId, $groupIds): void {
                $query->where(function (Builder $query) use ($userId): void {
                    $query->where('subject_type', 'user')
                        ->where('subject_id', $userId)
                        ->whereNull('subject_relation');
                });

                if ($groupIds !== []) {
                    $query->orWhere(function (Builder $query) use ($groupIds): void {
                        $query->where('subject_type', GroupService::OBJECT_TYPE)
                            ->whereIn('subject_id', $groupIds)
                            ->where('subject_relation', GroupService::MEMBER_RELATION);
                    });
                }
            })
            ->pluck('relation');

        $roles = [];

        foreach ($relations as $relation) {
            if (is_string($relation)) {
                $roles[] = MembershipRole::from($relation);
            }
        }

        return $roles;
    }

    /**
     * @param  array<int, MembershipRole>  $candidates
     */
    private function highest(array $candidates): ?MembershipRole
    {
        $best = null;

        foreach ($candidates as $role) {
            if ($best === null || $role->outranks($best)) {
                $best = $role;
            }
        }

        return $best;
    }

    private function tuple(string $organizationId, GrantSubject $subject, MembershipRole $role, ResourceRef $resource): Relationship
    {
        return new Relationship(
            $organizationId,
            $resource->type,
            $resource->id,
            $role->value,
            $subject->type,
            $subject->id,
            $subject->subjectRelation(),
        );
    }

    /**
     * @return list<string>
     */
    private static function roleValues(): array
    {
        return array_map(static fn (MembershipRole $role): string => $role->value, MembershipRole::cases());
    }

    private function emitAndAudit(string $organizationId, string $action, GrantSubject $subject, MembershipRole $role, ResourceRef $resource): void
    {
        $context = [
            'subject_type' => $subject->type,
            'subject_id' => $subject->id,
            'role' => $role->value,
            'resource_type' => $resource->type,
            'resource_id' => $resource->id,
        ];

        $this->events->emit(new DomainEvent($action, $context, $organizationId));

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::System,
            organizationId: $organizationId,
            targetType: $resource->type,
            targetId: $resource->id,
            context: $context,
        ));
    }
}
