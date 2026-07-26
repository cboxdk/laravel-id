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
use Cbox\Id\Scim\Enums\ScimPatchOp;
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

    public function list(Directory $directory, string $filter, ?int $startIndex, ?int $count, bool $withMembers = false): DirectoryPage
    {
        $query = DirectoryGroup::query()->where('directory_id', $directory->id);

        if ($filter !== '') {
            // The two equality filters IdPs actually send against /Groups:
            // `displayName eq "x"` (Okta's membership-sync existence check) and
            // `externalId eq "x"` — which Entra sends on EVERY cycle to locate the
            // group it already provisioned. Refusing externalId returned a flat 400 to
            // the first call of every sync, which Entra escalates into a quarantined
            // provisioning job rather than a degraded one.
            if (preg_match('/^(?<attr>displayName|externalId)\s+eq\s+"(?<val>[^"]*)"$/i', trim($filter), $m) !== 1) {
                throw UnsupportedDirectoryFilter::make($filter);
            }

            // RFC 7643 §2.1: the attribute NAME is case-insensitive. Its value is not —
            // `externalId` is a client-assigned opaque identifier, compared as issued.
            $query->where(strtolower($m['attr']) === 'externalid' ? 'external_id' : 'display_name', $m['val']);
        }

        $total = (clone $query)->count();

        $start = max(1, $startIndex ?? 1);
        $limit = min(self::MAX_PAGE, max(0, $count ?? self::MAX_PAGE));

        // Membership is loaded only when the caller asked for it. Eager-loading it
        // unconditionally meant a page of 200 groups hydrated EVERY member of every
        // one of them: against an enterprise directory with several 20,000-member
        // groups — which is the exact shape Entra ID syncs — one `GET /Groups?count=200`
        // built hundreds of thousands of models to answer. That is an out-of-memory,
        // not a slow response.
        $resources = $query
            ->when($withMembers, static fn ($builder) => $builder->with('members'))
            ->orderBy('id')
            ->offset($start - 1)
            ->limit($limit)
            ->get();

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
        // Deny-by-default: only add/remove/replace are defined for SCIM PATCH
        // (RFC 7644 §3.5.2). An unknown op is a client error, not a silent no-op that
        // returns 200 with nothing changed. The closed set lives in ONE place — the
        // enum — so this surface and the User mapper cannot drift apart again.
        $op = ScimPatchOp::tryParse($operation['op'] ?? null)
            ?? throw UnsupportedGroupPatch::op(ScimPatchOp::label($operation['op'] ?? null));

        $path = is_string($operation['path'] ?? null) ? trim($operation['path']) : '';
        $value = $operation['value'] ?? null;

        // RFC 7643 §2.1: "Attribute names are case insensitive." That governs the
        // `path` and the keys inside a pathless `value` exactly as it governs `op`, so
        // every comparison below is made against the folded spelling. Matching
        // `displayName`/`members` byte-for-byte meant an IdP that sent `displayname`
        // got a 400 for a rename this server understood perfectly well.
        $canonical = strtolower($path);

        // Rename: replace with a displayName in the value (path or pathless).
        $displayName = is_array($value) ? self::attribute($value, 'displayName') : null;

        if ($op === ScimPatchOp::Replace && is_string($displayName)) {
            $group->forceFill(['display_name' => $displayName])->save();

            return;
        }

        if ($op === ScimPatchOp::Replace && $canonical === 'displayname' && is_string($value)) {
            $group->forceFill(['display_name' => $value])->save();

            return;
        }

        // Beyond displayName (handled above) and the pathless whole-resource form,
        // only the `members` attribute is addressable. A bogus path is refused rather
        // than silently ignored.
        if (! str_starts_with($canonical, 'members') && $canonical !== '') {
            throw UnsupportedGroupPatch::path($path);
        }

        // Where the member payload lives: a `members`-pathed op carries the id list
        // directly as $value; a PATHLESS op carries the whole resource, so the members
        // live under its `members` key. Reading $value directly for the pathless form
        // extracted ZERO ids from `{members:[…]}` and then sync([]) WIPED every member.
        $memberValue = $canonical === '' && is_array($value) ? self::attribute($value, 'members') : $value;

        // A pathless replace that doesn't carry `members` at all is a resource replace
        // that must not touch membership — never let it fall through to sync([]).
        if ($op === ScimPatchOp::Replace && $canonical === '' && $memberValue === null) {
            return;
        }

        // The enum closes the set, so the match is exhaustive without a default arm.
        // `remove` gets the path AS SENT: its value filter carries a member id, and
        // folding that would look up a lower-cased ULID that matches nothing.
        match ($op) {
            ScimPatchOp::Add => $group->members()->syncWithoutDetaching($this->resolveMembers($group->directory_id, $this->valueIds($memberValue))),
            ScimPatchOp::Replace => $group->members()->sync($this->resolveMembers($group->directory_id, $this->valueIds($memberValue))),
            ScimPatchOp::Remove => $this->removeMembers($group, $path, $memberValue),
        };
    }

    /**
     * Read one attribute out of a PATCH `value` object by its case-insensitive name
     * (RFC 7643 §2.1).
     *
     * @param  array<array-key, mixed>  $value
     */
    private static function attribute(array $value, string $name): mixed
    {
        return array_change_key_case($value, CASE_LOWER)[strtolower($name)] ?? null;
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
