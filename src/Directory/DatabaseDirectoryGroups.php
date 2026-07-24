<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Exceptions\UnsupportedGroupPatch;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\DirectoryPage;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Illuminate\Support\Facades\DB;

/**
 * The default {@see DirectoryGroups} implementation over `directory_groups` and
 * its membership pivot. All the group query, SCIM PATCH semantics and membership
 * resolution the SCIM controller used to inline live here, behind the contract.
 *
 * Membership-changing operations emit `directory.group.membership_changed` so the
 * access-control layer can reconcile group→role assignments — the SCIM→role bridge.
 */
class DatabaseDirectoryGroups implements DirectoryGroups
{
    private const MAX_PAGE = 200;

    public function __construct(private readonly EventBus $events) {}

    public function list(Directory $directory, string $filter, ?int $startIndex, ?int $count): DirectoryPage
    {
        $query = DirectoryGroup::query()->where('directory_id', $directory->id);

        if ($filter !== '') {
            // Groups are overwhelmingly filtered by `displayName eq "x"` (the
            // membership-sync existence check). Support just that.
            if (preg_match('/^displayName\s+eq\s+"([^"]*)"$/i', trim($filter), $m) !== 1) {
                throw UnsupportedDirectoryFilter::make($filter);
            }

            $query->where('display_name', $m[1]);
        }

        $total = (clone $query)->count();

        $start = max(1, $startIndex ?? 1);
        $limit = min(self::MAX_PAGE, max(0, $count ?? self::MAX_PAGE));

        $resources = $query->with('members')->orderBy('id')->offset($start - 1)->limit($limit)->get();

        return new DirectoryPage($resources, $total, $start);
    }

    public function find(Directory $directory, string $id): ?DirectoryGroup
    {
        $group = DirectoryGroup::query()->where('directory_id', $directory->id)->whereKey($id)->first();

        return $group?->load('members');
    }

    public function create(Directory $directory, string $displayName, ?string $externalId, array $memberIds): DirectoryGroup
    {
        $group = DirectoryGroup::query()->create([
            'directory_id' => $directory->id,
            'display_name' => $displayName,
            'external_id' => $externalId,
        ]);

        $group->members()->sync($this->resolveMembers($directory->id, $memberIds));

        $this->emitMembershipChanged($group->id, $directory->organization_id);

        return $group->load('members');
    }

    public function replace(DirectoryGroup $group, ?string $displayName, ?string $externalId, array $memberIds): DirectoryGroup
    {
        $group->forceFill(array_filter([
            'display_name' => $displayName,
            'external_id' => $externalId,
        ], static fn (mixed $v): bool => $v !== null))->save();

        // PUT is a full replace: membership becomes exactly the supplied set.
        $group->members()->sync($this->resolveMembers($group->directory_id, $memberIds));

        $this->emitMembershipChanged($group->id, $this->organizationOf($group->directory_id));

        return $group->load('members');
    }

    public function applyPatch(DirectoryGroup $group, array $operations): DirectoryGroup
    {
        // SCIM PATCH is atomic (RFC 7644 §3.5.2): if any operation fails the whole
        // request fails with no partial change. Wrap the ops so a later invalid op
        // rolls back the earlier ones instead of leaving the group half-edited — and
        // the membership event only fires on a fully-applied patch.
        DB::transaction(function () use ($group, $operations): void {
            foreach ($operations as $operation) {
                if (is_array($operation)) {
                    $this->applyOperation($group, $operation);
                }
            }
        });

        $this->emitMembershipChanged($group->id, $this->organizationOf($group->directory_id));

        return $group->load('members');
    }

    public function delete(DirectoryGroup $group): void
    {
        // Capture the org before the row is gone, then reconcile after — so prior
        // members lose the roles the group granted.
        $organizationId = $this->organizationOf($group->directory_id);

        $group->members()->detach();
        $group->delete();

        $this->emitMembershipChanged($group->id, $organizationId);
    }

    private function emitMembershipChanged(string $groupId, ?string $organizationId): void
    {
        $this->events->emit(new DomainEvent(
            'directory.group.membership_changed',
            ['group_id' => $groupId, 'organization_id' => $organizationId],
            $organizationId,
        ));
    }

    private function organizationOf(string $directoryId): ?string
    {
        $organizationId = Directory::query()->whereKey($directoryId)->value('organization_id');

        return is_string($organizationId) ? $organizationId : null;
    }

    /**
     * Apply one SCIM PATCH operation (add/remove/replace) to the group.
     *
     * @param  array<array-key, mixed>  $operation
     */
    private function applyOperation(DirectoryGroup $group, array $operation): void
    {
        $op = strtolower(is_string($operation['op'] ?? null) ? $operation['op'] : '');
        $path = is_string($operation['path'] ?? null) ? $operation['path'] : '';
        $value = $operation['value'] ?? null;

        // Deny-by-default: only add/remove/replace are defined for SCIM PATCH
        // (RFC 7644 §3.5.2). An unknown op is a client error, not a silent no-op that
        // returns 200 with nothing changed.
        if (! in_array($op, ['add', 'remove', 'replace'], true)) {
            throw UnsupportedGroupPatch::op($op);
        }

        // Rename: replace with a displayName in the value (path or pathless).
        if ($op === 'replace' && is_array($value) && isset($value['displayName']) && is_string($value['displayName'])) {
            $group->forceFill(['display_name' => $value['displayName']])->save();

            return;
        }

        if ($op === 'replace' && $path === 'displayName' && is_string($value)) {
            $group->forceFill(['display_name' => $value])->save();

            return;
        }

        // Beyond displayName (handled above) and the pathless whole-resource form,
        // only the `members` attribute is addressable. A bogus path is refused rather
        // than silently ignored.
        if (! str_starts_with($path, 'members') && $path !== '') {
            throw UnsupportedGroupPatch::path($path);
        }

        // Where the member payload lives: a `members`-pathed op carries the id list
        // directly as $value; a PATHLESS op carries the whole resource, so the members
        // live under its `members` key. Reading $value directly for the pathless form
        // extracted ZERO ids from `{members:[…]}` and then sync([]) WIPED every member.
        $memberValue = $path === '' && is_array($value) ? ($value['members'] ?? null) : $value;

        // A pathless replace that doesn't carry `members` at all is a resource replace
        // that must not touch membership — never let it fall through to sync([]).
        if ($op === 'replace' && $path === '' && $memberValue === null) {
            return;
        }

        // $op is guaranteed to be add/remove/replace (validated above), so the match
        // is exhaustive without a default arm.
        match ($op) {
            'add' => $group->members()->syncWithoutDetaching($this->resolveMembers($group->directory_id, $this->valueIds($memberValue))),
            'replace' => $group->members()->sync($this->resolveMembers($group->directory_id, $this->valueIds($memberValue))),
            'remove' => $this->removeMembers($group, $path, $memberValue),
        };
    }

    private function removeMembers(DirectoryGroup $group, string $path, mixed $value): void
    {
        // `members[value eq "<id>"]` removes one; bare `members` clears all.
        if (preg_match('/members\[\s*value\s+eq\s+"([^"]+)"\s*\]/i', $path, $m) === 1) {
            $group->members()->detach($m[1]);

            return;
        }

        $ids = $this->valueIds($value);

        if ($ids === []) {
            $group->members()->detach();

            return;
        }

        $group->members()->detach($this->resolveMembers($group->directory_id, $ids));
    }

    /**
     * Extract member ids from a PATCH `value` — a list of `{value: id}` objects or
     * bare id strings.
     *
     * @return list<string>
     */
    private function valueIds(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $ids = [];

        foreach ($value as $item) {
            $id = is_array($item) ? ($item['value'] ?? null) : $item;

            if (is_string($id) && $id !== '') {
                $ids[] = $id;
            }
        }

        return array_values(array_unique($ids));
    }

    /**
     * Keep only member ids that are real users in this directory (ignore unknowns
     * rather than error, matching lenient IdP expectations).
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private function resolveMembers(string $directoryId, array $ids): array
    {
        if ($ids === []) {
            return [];
        }

        $found = DirectoryUser::query()
            ->where('directory_id', $directoryId)
            ->whereIn('id', $ids)
            ->pluck('id')
            ->all();

        return array_values(array_filter($found, 'is_string'));
    }
}
