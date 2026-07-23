<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Authorization\Contracts\RelationshipStore;
use Cbox\Id\Kernel\Authorization\Models\RelationshipTuple;
use Cbox\Id\Kernel\Authorization\ValueObjects\Relationship;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\GenericTenant;
use Cbox\Id\Organization\Contracts\Groups;
use Cbox\Id\Organization\Exceptions\GroupNameTaken;
use Cbox\Id\Organization\Models\UserGroup;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;

/**
 * Groups with tuple-backed membership: the `user_groups` table holds metadata
 * only, and "who is in the group" is relationship tuples
 * (`user_group:<id> #member @user:<id>`). A grant to the group is a userset
 * tuple, so group-inherited access resolves through the store's expansion —
 * one membership store, no drift between a table and the graph.
 */
class GroupService implements Groups
{
    /** Tuple vocabulary for groups; shared with {@see ResourceAccessService}. */
    public const OBJECT_TYPE = 'user_group';

    public const MEMBER_RELATION = 'member';

    public function __construct(
        private readonly TenantContext $tenant,
        private readonly RelationshipStore $relationships,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function create(string $organizationId, string $name): UserGroup
    {
        return $this->tenant->runAs(GenericTenant::of($organizationId), fn (): UserGroup => DB::transaction(function () use ($organizationId, $name): UserGroup {
            if (UserGroup::query()->where('name', $name)->exists()) {
                throw GroupNameTaken::make($organizationId, $name);
            }

            $group = new UserGroup;
            $group->fill(['name' => $name]);
            $group->save();

            $this->emitAndAudit($organizationId, $group->id, 'organization.group_created', ['name' => $name]);

            return $group;
        }));
    }

    public function delete(string $organizationId, string $groupId): void
    {
        $this->tenant->runAs(GenericTenant::of($organizationId), fn () => DB::transaction(function () use ($organizationId, $groupId): void {
            $group = UserGroup::query()->whereKey($groupId)->first();

            if ($group === null) {
                return;
            }

            // Membership tuples (group as object) AND grant tuples (group as
            // userset subject) go with the group — a deleted group must never
            // keep conferring access.
            RelationshipTuple::query()
                ->where('object_type', self::OBJECT_TYPE)
                ->where('object_id', $groupId)
                ->delete();

            RelationshipTuple::query()
                ->where('subject_type', self::OBJECT_TYPE)
                ->where('subject_id', $groupId)
                ->delete();

            $group->delete();

            $this->emitAndAudit($organizationId, $groupId, 'organization.group_deleted', ['name' => $group->name]);
        }));
    }

    public function addMember(string $organizationId, string $groupId, string $userId): void
    {
        $this->requireGroup($organizationId, $groupId);

        $this->relationships->write(new Relationship(
            $organizationId,
            self::OBJECT_TYPE,
            $groupId,
            self::MEMBER_RELATION,
            'user',
            $userId,
        ));

        $this->emitAndAudit($organizationId, $groupId, 'organization.group_member_added', ['user_id' => $userId]);
    }

    public function removeMember(string $organizationId, string $groupId, string $userId): void
    {
        $this->relationships->delete(new Relationship(
            $organizationId,
            self::OBJECT_TYPE,
            $groupId,
            self::MEMBER_RELATION,
            'user',
            $userId,
        ));

        $this->emitAndAudit($organizationId, $groupId, 'organization.group_member_removed', ['user_id' => $userId]);
    }

    public function members(string $organizationId, string $groupId): array
    {
        return $this->tenant->runAs(GenericTenant::of($organizationId), function () use ($groupId): array {
            $ids = RelationshipTuple::query()
                ->where('object_type', self::OBJECT_TYPE)
                ->where('object_id', $groupId)
                ->where('relation', self::MEMBER_RELATION)
                ->where('subject_type', 'user')
                ->whereNull('subject_relation')
                ->orderBy('subject_id')
                ->pluck('subject_id');

            $members = [];

            foreach ($ids as $id) {
                if (is_string($id)) {
                    $members[] = $id;
                }
            }

            return $members;
        });
    }

    public function groupsFor(string $organizationId, string $userId): Collection
    {
        return $this->tenant->runAs(GenericTenant::of($organizationId), function () use ($userId): Collection {
            $groupIds = RelationshipTuple::query()
                ->where('object_type', self::OBJECT_TYPE)
                ->where('relation', self::MEMBER_RELATION)
                ->where('subject_type', 'user')
                ->where('subject_id', $userId)
                ->whereNull('subject_relation')
                ->pluck('object_id');

            return UserGroup::query()->whereIn('id', $groupIds)->orderBy('name')->get();
        });
    }

    public function forOrganization(string $organizationId): Collection
    {
        return $this->tenant->runAs(
            GenericTenant::of($organizationId),
            fn (): Collection => UserGroup::query()->orderBy('name')->get(),
        );
    }

    private function requireGroup(string $organizationId, string $groupId): void
    {
        $this->tenant->runAs(
            GenericTenant::of($organizationId),
            fn () => UserGroup::query()->whereKey($groupId)->firstOrFail(),
        );
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function emitAndAudit(string $organizationId, string $groupId, string $action, array $context): void
    {
        $this->events->emit(new DomainEvent($action, ['group_id' => $groupId] + $context, $organizationId));

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::System,
            organizationId: $organizationId,
            targetType: self::OBJECT_TYPE,
            targetId: $groupId,
            context: $context,
        ));
    }
}
