<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Contracts\DirectoryGroupSearch;
use Cbox\Id\Directory\Exceptions\DirectoryGroupNameTaken;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Exceptions\UnsupportedGroupPatch;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\Support\ScimDirectoryQuery;
use Cbox\Id\Directory\Support\ScimQueryAttributes;
use Cbox\Id\Directory\ValueObjects\DirectoryPage;
use Cbox\Id\Directory\ValueObjects\DirectorySearch;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Scim\Enums\ScimPatchOp;
use Cbox\Id\Scim\Exceptions\InvalidScimFilter;
use Cbox\Id\Scim\Filter\Nodes\FilterNode;
use Cbox\Id\Scim\Filter\ScimFilterParser;
use Cbox\Id\Scim\Filter\ScimPatchPath;
use Cbox\Id\Scim\ScimSchema;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;

/**
 * The default {@see DirectoryGroups} implementation over `directory_groups` and
 * its membership pivot. All the group query, SCIM PATCH semantics and membership
 * resolution the SCIM controller used to inline live here, behind the contract.
 *
 * Membership-changing operations emit `directory.group.membership_changed` so the
 * access-control layer can reconcile group→role assignments — the SCIM→role bridge.
 */
class DatabaseDirectoryGroups implements DirectoryGroups, DirectoryGroupSearch
{
    private const MAX_PAGE = 200;

    public function __construct(private readonly EventBus $events) {}

    public function list(Directory $directory, string $filter, ?int $startIndex, ?int $count, bool $withMembers = false): DirectoryPage
    {
        return $this->search($directory, new DirectorySearch($filter, $startIndex, $count), $withMembers);
    }

    public function search(Directory $directory, DirectorySearch $search, bool $withMembers = false): DirectoryPage
    {
        $query = DirectoryGroup::query()->where('directory_id', $directory->id);

        // The full filter grammar over the group attributes the store holds —
        // `displayName eq "x"` (Okta's existence check, Entra's matching attribute),
        // `externalId eq "x"` (which Entra sends on EVERY cycle), and membership
        // (`members[value eq "<user id>"]`), evaluated as an EXISTS so a page of groups
        // never loads the members it is filtering on.
        (new ScimDirectoryQuery(ScimQueryAttributes::groups()))->apply($query, $search);

        $total = (clone $query)->reorder()->count();

        $start = max(1, $search->startIndex ?? 1);
        $limit = min(self::MAX_PAGE, max(0, $search->count ?? self::MAX_PAGE));

        // Membership is loaded only when the caller asked for it. Eager-loading it
        // unconditionally meant a page of 200 groups hydrated EVERY member of every
        // one of them: against an enterprise directory with several 20,000-member
        // groups — which is the exact shape Entra ID syncs — one `GET /Groups?count=200`
        // built hundreds of thousands of models to answer. That is an out-of-memory,
        // not a slow response.
        $resources = $query
            ->when($withMembers, static fn ($builder) => $builder->with('members'))
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
        try {
            $group = DirectoryGroup::query()->create([
                'directory_id' => $directory->id,
                'display_name' => $displayName,
                'external_id' => $externalId,
            ]);
        } catch (UniqueConstraintViolationException) {
            // Display names are unique per directory (the table's own unique index).
            // The violation used to escape as a 500; it is a 409 `uniqueness`.
            throw DirectoryGroupNameTaken::make($displayName);
        }

        $group->members()->sync($this->resolveMembers($directory->id, $memberIds));

        $this->emitMembershipChanged($group->id, $directory->organization_id);

        return $group->load('members');
    }

    public function replace(DirectoryGroup $group, ?string $displayName, ?string $externalId, array $memberIds): DirectoryGroup
    {
        try {
            $group->forceFill(array_filter([
                'display_name' => $displayName,
                'external_id' => $externalId,
            ], static fn (mixed $v): bool => $v !== null))->save();
        } catch (UniqueConstraintViolationException) {
            throw DirectoryGroupNameTaken::make($displayName ?? $group->display_name);
        }

        // PUT is a full replace: membership becomes exactly the supplied set.
        $changes = $group->members()->sync($this->resolveMembers($group->directory_id, $memberIds));

        if (self::changed($changes)) {
            $group->recordRevision();
        }

        $this->emitMembershipChanged($group->id, $this->organizationOf($group->directory_id));

        return $group->load('members');
    }

    public function applyPatch(DirectoryGroup $group, array $operations): DirectoryGroup
    {
        // SCIM PATCH is atomic (RFC 7644 §3.5.2): if any operation fails the whole
        // request fails with no partial change. Wrap the ops so a later invalid op
        // rolls back the earlier ones instead of leaving the group half-edited — and
        // the membership event only fires on a fully-applied patch.
        try {
            DB::transaction(function () use ($group, $operations): void {
                $membershipChanged = false;

                foreach ($operations as $operation) {
                    if (is_array($operation)) {
                        $membershipChanged = $this->applyOperation($group, $operation) || $membershipChanged;
                    }
                }

                // A membership edit lands in the pivot, never on the group row, so the
                // group's revision (its ETag) is moved explicitly.
                if ($membershipChanged) {
                    $group->recordRevision();
                }
            });
        } catch (UniqueConstraintViolationException) {
            $group->refresh();

            throw DirectoryGroupNameTaken::make($group->display_name);
        }

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
     * Apply one SCIM PATCH operation (add/remove/replace) to the group, answering
     * whether it changed the membership.
     *
     * The path is parsed by the RFC 7644 §3.5.2 grammar (`PATH = attrPath / valuePath
     * [subAttr]`) and the value filter of a `remove` is evaluated, so every spelling an
     * IdP sends lands on the same code:
     *
     * - `displayName` — `replace` (Entra, `"op": "Replace"`) or `add`, which on a
     *   single-valued attribute is a replace (§3.5.2.1);
     * - `externalId` — set or cleared;
     * - `members` — `add` attaches, `replace` sets exactly (Okta), `remove` with a value
     *   list detaches those (Entra, `"op": "Remove", "value": [{"value": id}]`) and with
     *   no value detaches all;
     * - `members[value eq "<id>"]`, and any other value filter over `value`, `display`,
     *   `type` — `remove` detaches exactly the members the filter selects;
     * - pathless — a partial resource whose `displayName`, `externalId` and `members`
     *   are applied as above (Okta's rename sends `{"id": …, "displayName": …}`).
     *
     * @param  array<array-key, mixed>  $operation
     */
    private function applyOperation(DirectoryGroup $group, array $operation): bool
    {
        // Deny-by-default: only add/remove/replace are defined for SCIM PATCH
        // (RFC 7644 §3.5.2). An unknown op is a client error, not a silent no-op that
        // returns 200 with nothing changed. The closed set lives in ONE place — the
        // enum — so this surface and the User mapper cannot drift apart again.
        $op = ScimPatchOp::tryParse($operation['op'] ?? null)
            ?? throw UnsupportedGroupPatch::op(ScimPatchOp::label($operation['op'] ?? null));

        $rawPath = is_string($operation['path'] ?? null) ? trim($operation['path']) : '';
        $value = $operation['value'] ?? null;

        if ($rawPath === '') {
            return $this->applyPathless($group, $op, $value);
        }

        $path = $this->parsePath($rawPath);

        // RFC 7643 §2.1: "Attribute names are case insensitive." That governs the
        // `path` and the keys inside a pathless `value` exactly as it governs `op`.
        $attribute = strtolower($path->attribute->attribute);
        $sub = $path->attribute->subAttribute ?? $path->subAttribute;

        if ($attribute === 'displayname' && $path->filter === null && $sub === null) {
            // displayName is REQUIRED (RFC 7643 §4.2): it can be replaced, not removed.
            if ($op === ScimPatchOp::Remove || ! is_string($value) || $value === '') {
                throw UnsupportedGroupPatch::path($rawPath);
            }

            $group->forceFill(['display_name' => $value])->save();

            return false;
        }

        if ($attribute === 'externalid' && $path->filter === null && $sub === null) {
            if ($op !== ScimPatchOp::Remove && (! is_string($value) || $value === '')) {
                throw UnsupportedGroupPatch::path($rawPath);
            }

            $group->forceFill(['external_id' => $op === ScimPatchOp::Remove ? null : $value])->save();

            return false;
        }

        // Beyond those two, only `members` is addressable. A bogus path is refused
        // rather than silently ignored.
        if ($attribute !== 'members') {
            throw UnsupportedGroupPatch::path($rawPath);
        }

        // `members.value`, `members[value eq "x"].display`: a SUB-ATTRIBUTE of a member,
        // not the membership list. This server stores no per-membership value to write,
        // and treating the shape as a membership write used to detach every member (an
        // id list read out of a plain string is empty). Refused.
        if ($sub !== null) {
            throw UnsupportedGroupPatch::path($rawPath);
        }

        if ($path->filter !== null) {
            // `remove` with a value filter is how an IdP detaches ONE member. `add` and
            // `replace` on a filtered path name a member's sub-attributes, which are
            // read-only here — and the old reading of that shape was a silent wipe.
            if ($op !== ScimPatchOp::Remove) {
                throw UnsupportedGroupPatch::path($rawPath);
            }

            return $this->removeSelected($group, $path->filter, $rawPath);
        }

        // The enum closes the set, so the match is exhaustive without a default arm.
        return match ($op) {
            ScimPatchOp::Add => self::changed($group->members()->syncWithoutDetaching($this->resolveMembers($group->directory_id, $this->valueIds($value)))),
            ScimPatchOp::Replace => self::changed($group->members()->sync($this->resolveMembers($group->directory_id, $this->valueIds($value)))),
            ScimPatchOp::Remove => $this->removeMembers($group, $value),
        };
    }

    /**
     * A pathless operation: `value` is a partial resource.
     */
    private function applyPathless(DirectoryGroup $group, ScimPatchOp $op, mixed $value): bool
    {
        // A pathless REMOVE names nothing at all. RFC 7644 §3.5.2.2 requires 400/noTarget,
        // which is what the User path answers — this one used to let it through to a
        // detach of everything and return 200. Because membership drives the group→role
        // bridge, every mapped role went with it.
        if ($op === ScimPatchOp::Remove) {
            throw UnsupportedGroupPatch::noTarget();
        }

        if (! is_array($value)) {
            throw UnsupportedGroupPatch::notAnObject();
        }

        $displayName = self::attribute($value, 'displayName');
        $externalId = self::attribute($value, 'externalId');

        if (is_string($displayName) && $displayName !== '') {
            $group->forceFill(['display_name' => $displayName])->save();
        }

        if (is_string($externalId) && $externalId !== '') {
            $group->forceFill(['external_id' => $externalId])->save();
        }

        // A pathless op carries the WHOLE resource, so one that names both a displayName
        // and members means both — but one that carries no `members` at all must never
        // touch membership (it would otherwise sync to the empty set and wipe it).
        $members = self::attribute($value, 'members');

        if ($members === null) {
            return false;
        }

        $ids = $this->resolveMembers($group->directory_id, $this->valueIds($members));

        return self::changed($op === ScimPatchOp::Add
            ? $group->members()->syncWithoutDetaching($ids)
            : $group->members()->sync($ids));
    }

    /**
     * @throws UnsupportedGroupPatch
     */
    private function parsePath(string $path): ScimPatchPath
    {
        try {
            $parsed = (new ScimFilterParser)->parsePath($path);
        } catch (InvalidScimFilter) {
            throw UnsupportedGroupPatch::path($path);
        }

        // Fully qualified with the core Group URN is the same attribute; any other URN
        // names an extension this server does not implement.
        if ($parsed->attribute->schema !== null && ! $parsed->attribute->inSchema(ScimSchema::GROUP_URN)) {
            throw UnsupportedGroupPatch::path($path);
        }

        return $parsed;
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

    /**
     * Detach the members a value filter selects — `members[value eq "<id>"]`, or any
     * filter over a member's `value`, `display` and `type`.
     *
     * Evaluated in SQL over the membership relation, with the same translator the
     * `/Groups` filter uses, so a remove against a 20,000-member group does not load
     * 20,000 users to find one.
     */
    private function removeSelected(DirectoryGroup $group, FilterNode $filter, string $path): bool
    {
        $query = $group->members()->getQuery();

        try {
            (new ScimDirectoryQuery(ScimQueryAttributes::members()))->filter($query, $filter);
        } catch (UnsupportedDirectoryFilter) {
            throw UnsupportedGroupPatch::path($path);
        }

        $ids = array_values(array_filter($query->pluck('directory_users.id')->all(), is_string(...)));

        return $ids !== [] && $group->members()->detach($ids) > 0;
    }

    /**
     * `remove` on bare `members`: the members listed in `value` (Entra sends
     * `"value": [{"value": "<id>"}]`), or every member when there is no value.
     */
    private function removeMembers(DirectoryGroup $group, mixed $value): bool
    {
        $ids = $this->valueIds($value);

        if ($ids === []) {
            return $group->members()->detach() > 0;
        }

        return $group->members()->detach($this->resolveMembers($group->directory_id, $ids)) > 0;
    }

    /**
     * Whether a `sync()` result changed anything.
     *
     * @param  array<array-key, mixed>  $changes
     */
    private static function changed(array $changes): bool
    {
        foreach (['attached', 'detached', 'updated'] as $key) {
            if (($changes[$key] ?? []) !== []) {
                return true;
            }
        }

        return false;
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
