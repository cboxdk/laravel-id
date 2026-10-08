<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Scim;

use Cbox\Id\Api\Contracts\ScimGroupResources;
use Cbox\Id\Api\Exceptions\InvalidScimRequest;
use Cbox\Id\Api\Support\ScimAttributeSelection;
use Cbox\Id\Api\Support\ScimGroupMapper;
use Cbox\Id\Api\Support\ScimMapper;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Contracts\DirectoryGroupSearch;
use Cbox\Id\Directory\Exceptions\DirectoryGroupNameTaken;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectorySort;
use Cbox\Id\Directory\Exceptions\UnsupportedGroupPatch;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\ValueObjects\DirectorySearch;
use Cbox\Id\Scim\ScimSchema;
use Cbox\Id\Scim\Support\ScimETag;

/**
 * The `/Groups` operations (RFC 7643 §4.2, RFC 7644 §3) over the {@see DirectoryGroups}
 * domain — which owns the queries, PATCH semantics and membership resolution. This
 * class validates and maps SCIM, and is shared by `GroupController` and `/Bulk`.
 */
class DirectoryScimGroupResources implements ScimGroupResources
{
    public function __construct(private readonly DirectoryGroups $groups) {}

    public function location(string $id): string
    {
        return ScimGroupMapper::location($id);
    }

    public function list(Directory $directory, DirectorySearch $search, ScimAttributeSelection $selection): ScimOutcome
    {
        // Membership is off by default in a LISTING and loaded only when the client
        // asks (`?attributes=members`) — a page of 200 enterprise groups otherwise
        // serializes every member of every one of them. See ScimAttributeSelection.
        $withMembers = $selection->includeMembersInListing();

        try {
            if ($this->groups instanceof DirectoryGroupSearch) {
                $page = $this->groups->search($directory, $search, $withMembers);
            } elseif ($search->sortBy !== null) {
                throw UnsupportedDirectorySort::notSupported();
            } else {
                $page = $this->groups->list($directory, $search->filter, $search->startIndex, $search->count, $withMembers);
            }
        } catch (UnsupportedDirectoryFilter $e) {
            return ScimOutcome::error(400, $e->getMessage(), 'invalidFilter');
        } catch (UnsupportedDirectorySort $e) {
            return ScimOutcome::error(400, $e->getMessage(), 'invalidValue');
        }

        $resources = array_values($page->resources
            ->map(static fn (DirectoryGroup $group): array => ScimGroupMapper::toResource($group, $withMembers))
            ->all());

        return ScimOutcome::resource(ScimMapper::listResponse($resources, $page->total, $page->startIndex, count($resources)));
    }

    public function show(Directory $directory, string $id, ScimAttributeSelection $selection, ?string $ifNoneMatch = null): ScimOutcome
    {
        $group = $this->groups->find($directory, $id);

        if ($group === null) {
            return $this->notFound();
        }

        $version = ScimGroupMapper::version($group);

        if (ScimETag::ifNoneMatchHolds($version, $ifNoneMatch)) {
            return ScimOutcome::notModified($version, ScimGroupMapper::location($group->id));
        }

        // Reading ONE group returns its membership by default — asking for a single
        // group is how a client asks for its members — unless it was excluded.
        return ScimOutcome::resource(ScimGroupMapper::toResource($group, $selection->includeMembers()));
    }

    public function create(Directory $directory, array $body): ScimOutcome
    {
        $body = self::keyed($body);
        $displayName = ScimGroupMapper::displayName($body);

        if ($displayName === null) {
            return ScimOutcome::error(400, 'displayName is required.', 'invalidValue');
        }

        // RFC 7644 §3.3 — and Microsoft Entra ID matches groups on displayName, so its
        // validator POSTs the same group twice and requires the second to be a 409.
        if ($this->nameTaken($directory, $displayName, null)) {
            return $this->nameConflict();
        }

        try {
            $group = $this->groups->create(
                $directory,
                $displayName,
                ScimGroupMapper::externalId($body),
                ScimGroupMapper::memberIds($body),
            );
        } catch (DirectoryGroupNameTaken) {
            return $this->nameConflict();
        }

        return ScimOutcome::resource(ScimGroupMapper::toResource($group), 201);
    }

    public function replace(Directory $directory, string $id, array $body, ?string $ifMatch = null): ScimOutcome
    {
        $group = $this->groups->find($directory, $id);

        if ($group === null) {
            return $this->notFound();
        }

        if (ScimETag::ifMatchFails(ScimGroupMapper::version($group), $ifMatch)) {
            return ScimOutcome::preconditionFailed(ScimGroupMapper::location($group->id));
        }

        $body = self::keyed($body);

        // PUT is a full replacement (RFC 7644 §3.5.1) and `displayName` is the sole
        // required Group attribute (RFC 7643 §4.2) — a PUT without it is invalid, not
        // a silent no-change.
        $displayName = ScimGroupMapper::displayName($body);
        if ($displayName === null) {
            return ScimOutcome::error(400, 'displayName is required.', 'invalidValue');
        }

        if ($this->nameTaken($directory, $displayName, $group->id)) {
            return $this->nameConflict();
        }

        try {
            $group = $this->groups->replace(
                $group,
                $displayName,
                ScimGroupMapper::externalId($body),
                ScimGroupMapper::memberIds($body),
            );
        } catch (DirectoryGroupNameTaken) {
            return $this->nameConflict();
        }

        return ScimOutcome::resource(ScimGroupMapper::toResource($group));
    }

    public function patch(Directory $directory, string $id, array $body, ?string $ifMatch = null): ScimOutcome
    {
        $group = $this->groups->find($directory, $id);

        if ($group === null) {
            return $this->notFound();
        }

        if (ScimETag::ifMatchFails(ScimGroupMapper::version($group), $ifMatch)) {
            return ScimOutcome::preconditionFailed(ScimGroupMapper::location($group->id));
        }

        try {
            // A missing or misspelled `Operations` used to degrade to `[]` and answer
            // 200 with the untouched group — the IdP then recorded the membership edit
            // as applied and never sent it again. A merely lower-cased `operations` is
            // legal SCIM (RFC 7643 §2.1) and is matched, not refused.
            $group = $this->groups->applyPatch($group, ScimPatchRequest::operations($body));
        } catch (InvalidScimRequest|UnsupportedGroupPatch $e) {
            return ScimOutcome::error(400, $e->getMessage(), $e->scimType);
        } catch (DirectoryGroupNameTaken) {
            return $this->nameConflict();
        }

        return ScimOutcome::resource(ScimGroupMapper::toResource($group));
    }

    public function delete(Directory $directory, string $id, ?string $ifMatch = null): ScimOutcome
    {
        $group = $this->groups->find($directory, $id);

        // RFC 7644 §3.6: a delete of an unknown id is a 404, not a 204 that tells the
        // IdP a group it never had is now gone.
        if ($group === null) {
            return $this->notFound();
        }

        if (ScimETag::ifMatchFails(ScimGroupMapper::version($group), $ifMatch)) {
            return ScimOutcome::preconditionFailed(ScimGroupMapper::location($group->id));
        }

        $this->groups->delete($group);

        return ScimOutcome::noContent(ScimGroupMapper::location($group->id));
    }

    /**
     * Whether another group of the directory already has this display name, compared
     * without regard to case — `displayName` is `caseExact: false` (RFC 7643 §4.2), so
     * "Engineering" and "engineering" are one name to a client matching on it.
     *
     * Asked through the store's own filter; a store that cannot answer it leaves the
     * decision to its own constraint ({@see DirectoryGroupNameTaken}).
     */
    private function nameTaken(Directory $directory, string $displayName, ?string $except): bool
    {
        $filter = ScimSchema::equalityFilter('displayName', $displayName);

        if ($except !== null) {
            $filter .= ' and not ('.ScimSchema::equalityFilter('id', $except).')';
        }

        try {
            return $this->groups->list($directory, $filter, 1, 0)->total > 0;
        } catch (UnsupportedDirectoryFilter) {
            return false;
        }
    }

    private function nameConflict(): ScimOutcome
    {
        return ScimOutcome::error(409, 'A group with this displayName already exists in this directory.', 'uniqueness');
    }

    /**
     * @param  array<array-key, mixed>  $body
     * @return array<string, mixed>
     */
    private static function keyed(array $body): array
    {
        $normalized = [];

        foreach ($body as $key => $value) {
            $normalized[(string) $key] = $value;
        }

        return $normalized;
    }

    private function notFound(): ScimOutcome
    {
        return ScimOutcome::error(404, 'Group not found.');
    }
}
