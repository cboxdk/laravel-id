<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\DirectoryPage;

/**
 * The default {@see DirectoryGroups} implementation over `directory_groups` and
 * its membership pivot. All the group query, SCIM PATCH semantics and membership
 * resolution the SCIM controller used to inline live here, behind the contract.
 */
final class DatabaseDirectoryGroups implements DirectoryGroups
{
    private const MAX_PAGE = 200;

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

        return $group->load('members');
    }

    public function applyPatch(DirectoryGroup $group, array $operations): DirectoryGroup
    {
        foreach ($operations as $operation) {
            if (is_array($operation)) {
                $this->applyOperation($group, $operation);
            }
        }

        return $group->load('members');
    }

    public function delete(DirectoryGroup $group): void
    {
        $group->members()->detach();
        $group->delete();
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

        // Rename: replace with a displayName in the value (path or pathless).
        if ($op === 'replace' && is_array($value) && isset($value['displayName']) && is_string($value['displayName'])) {
            $group->forceFill(['display_name' => $value['displayName']])->save();

            return;
        }

        if ($op === 'replace' && $path === 'displayName' && is_string($value)) {
            $group->forceFill(['display_name' => $value])->save();

            return;
        }

        if (! str_starts_with($path, 'members') && $path !== '') {
            return;
        }

        match ($op) {
            'add' => $group->members()->syncWithoutDetaching($this->resolveMembers($group->directory_id, $this->valueIds($value))),
            'replace' => $group->members()->sync($this->resolveMembers($group->directory_id, $this->valueIds($value))),
            'remove' => $this->removeMembers($group, $path, $value),
            default => null,
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
