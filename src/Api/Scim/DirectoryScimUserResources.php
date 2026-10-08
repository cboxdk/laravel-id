<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Scim;

use Cbox\Id\Api\Contracts\ScimUserResources;
use Cbox\Id\Api\Exceptions\InvalidScimRequest;
use Cbox\Id\Api\Support\ScimAttributes;
use Cbox\Id\Api\Support\ScimAttributeSelection;
use Cbox\Id\Api\Support\ScimMapper;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Contracts\DirectoryUsers;
use Cbox\Id\Directory\Contracts\DirectoryUserSearch;
use Cbox\Id\Directory\Exceptions\DirectoryUserNameTaken;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectorySort;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\DirectorySearch;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Identity\Exceptions\AccountExistsForEmail;
use Cbox\Id\Scim\ScimSchema;
use Cbox\Id\Scim\Support\ScimETag;

/**
 * The `/Users` operations over the Directory module: provisioning links the local
 * user, and deactivation or delete revokes its sessions instantly. Validation and
 * SCIM mapping happen here; the read/query side is {@see DirectoryUsers} and the
 * write side {@see DirectorySync}.
 *
 * Shared by `UserController` and `/Bulk`, so the two can never disagree.
 */
class DirectoryScimUserResources implements ScimUserResources
{
    public function __construct(
        private readonly DirectoryUsers $users,
        private readonly DirectorySync $sync,
    ) {}

    public function location(string $id): string
    {
        return ScimMapper::location($id);
    }

    public function list(Directory $directory, DirectorySearch $search, ScimAttributeSelection $selection): ScimOutcome
    {
        try {
            // Sorting is an optional capability of the store (DirectoryUserSearch). A
            // host store that only implements `list()` still answers filters and pages;
            // a `sortBy` it cannot honour is refused rather than silently ignored.
            if ($this->users instanceof DirectoryUserSearch) {
                $page = $this->users->search($directory, $search);
            } elseif ($search->sortBy !== null) {
                throw UnsupportedDirectorySort::notSupported();
            } else {
                $page = $this->users->list($directory, $search->filter, $search->startIndex, $search->count);
            }
        } catch (UnsupportedDirectoryFilter $e) {
            return ScimOutcome::error(400, $e->getMessage(), 'invalidFilter');
        } catch (UnsupportedDirectorySort $e) {
            return ScimOutcome::error(400, $e->getMessage(), 'invalidValue');
        }

        $resources = array_values($page->resources->map(ScimMapper::toResource(...))->all());

        return ScimOutcome::resource(ScimMapper::listResponse($resources, $page->total, $page->startIndex, count($resources)));
    }

    public function show(Directory $directory, string $id, ScimAttributeSelection $selection, ?string $ifNoneMatch = null): ScimOutcome
    {
        $user = $this->users->find($directory, $id);

        if ($user === null) {
            return $this->notFound();
        }

        $version = ScimMapper::version($user);

        // RFC 7644 §3.14: a conditional read of an unchanged resource is a 304 with an
        // empty body.
        if (ScimETag::ifNoneMatchHolds($version, $ifNoneMatch)) {
            return ScimOutcome::notModified($version, ScimMapper::location($user->id));
        }

        return ScimOutcome::resource(ScimMapper::toResource($user));
    }

    public function create(Directory $directory, array $body): ScimOutcome
    {
        // userName is REQUIRED (RFC 7643 §4.1.1). Without this an empty/absent userName
        // provisioned a 201 with a blank name — a resource the IdP can't address by
        // filter. Read case-insensitively, like the mapper (RFC 7643 §2.1).
        if (ScimAttributes::stringValue($body, 'userName') === '') {
            return ScimOutcome::error(400, 'userName is required.', 'invalidValue');
        }

        try {
            $scim = ScimMapper::fromArray($body);
        } catch (InvalidScimRequest $e) {
            return ScimOutcome::error(400, $e->getMessage(), $e->scimType);
        }

        // RFC 7644 §3.3: a create that "conflicts with existing resources" is a
        // `409 uniqueness`. Provisioning keys on externalId, so a second POST of the same
        // externalId used to update the existing row and answer 201 — telling the IdP it
        // had created a new resource when it had not. Both Okta's and Microsoft Entra
        // ID's conformance suites POST the same user twice and require the 409.
        if ($this->exists($directory, $scim->externalId)) {
            return ScimOutcome::error(409, 'A user with this externalId already exists in this directory.', 'uniqueness');
        }

        $result = $this->provision($directory->id, $scim);

        return $result instanceof ScimOutcome
            ? $result
            : ScimOutcome::resource(ScimMapper::toResource($result), 201);
    }

    public function replace(Directory $directory, string $id, array $body, ?string $ifMatch = null): ScimOutcome
    {
        $target = $this->users->find($directory, $id);

        if ($target === null) {
            return $this->notFound();
        }

        if (ScimETag::ifMatchFails(ScimMapper::version($target), $ifMatch)) {
            return ScimOutcome::preconditionFailed(ScimMapper::location($target->id));
        }

        // A full replace must still carry the required userName (RFC 7643 §4.1.1).
        if (ScimAttributes::stringValue($body, 'userName') === '') {
            return ScimOutcome::error(400, 'userName is required.', 'invalidValue');
        }

        // The URL identifies the resource; provisioning keys by externalId. A body
        // whose externalId names a DIFFERENT resource must not be honored — otherwise
        // `PUT /Users/A` with `externalId=B` would mutate/create B and leave A intact
        // (an IDOR). Bind the replace to the located row: reject an explicit mismatch.
        $bodyExternalId = ScimAttributes::stringValue($body, 'externalId');
        if ($bodyExternalId !== '' && $bodyExternalId !== $target->external_id) {
            return ScimOutcome::error(400, 'externalId does not match the target resource.', 'mutability');
        }

        // Full replace (PUT): re-provision from the submitted resource, PINNING the
        // externalId to the URL-located row. When the body omits externalId, the mapper
        // would otherwise fall back to `userName` and re-key the write to another row.
        try {
            $scim = ScimMapper::fromArray($body, $target->external_id);
        } catch (InvalidScimRequest $e) {
            return ScimOutcome::error(400, $e->getMessage(), $e->scimType);
        }

        $result = $this->provision($directory->id, $scim);

        return $result instanceof ScimOutcome ? $result : ScimOutcome::resource(ScimMapper::toResource($result));
    }

    public function patch(Directory $directory, string $id, array $body, ?string $ifMatch = null): ScimOutcome
    {
        $user = $this->users->find($directory, $id);

        if ($user === null) {
            return $this->notFound();
        }

        if (ScimETag::ifMatchFails(ScimMapper::version($user), $ifMatch)) {
            return ScimOutcome::preconditionFailed(ScimMapper::location($user->id));
        }

        // Apply the PATCH operations onto the current resource and re-provision.
        // Re-provisioning with active=false deactivates: drops membership and revokes
        // sessions immediately.
        try {
            $patched = ScimMapper::applyPatch($user, ScimPatchRequest::operations($body));
        } catch (InvalidScimRequest $e) {
            // RFC 7644 §3.5.2: a missing `Operations` member, an unmatched target, an
            // unknown/missing op or a non-boolean `active` are all errors. Answering 200
            // would make the IdP record a write that never happened and never retry it.
            return ScimOutcome::error(400, $e->getMessage(), $e->scimType);
        }

        $result = $this->provision($directory->id, $patched);

        return $result instanceof ScimOutcome ? $result : ScimOutcome::resource(ScimMapper::toResource($result));
    }

    public function delete(Directory $directory, string $id, ?string $ifMatch = null): ScimOutcome
    {
        $user = $this->users->find($directory, $id);

        // RFC 7644 §3.6: deleting a resource that does not exist is a 404. Answering
        // 204 told the IdP the deprovision succeeded for an id it never had.
        if ($user === null) {
            return $this->notFound();
        }

        if (ScimETag::ifMatchFails(ScimMapper::version($user), $ifMatch)) {
            return ScimOutcome::preconditionFailed(ScimMapper::location($user->id));
        }

        $this->sync->deprovisionUser($directory->id, $user->external_id);

        return ScimOutcome::noContent(ScimMapper::location($user->id));
    }

    /**
     * Whether the directory already holds a user under this externalId — asked through
     * the store's own filter, so a host store answers it too. A store that cannot
     * filter on externalId is not second-guessed here; provisioning then behaves as it
     * always has.
     */
    private function exists(Directory $directory, string $externalId): bool
    {
        try {
            return $this->users->list($directory, ScimSchema::equalityFilter('externalId', $externalId), 1, 0)->total > 0;
        } catch (UnsupportedDirectoryFilter) {
            return false;
        }
    }

    /**
     * Provision a user, translating the platform's no-silent-merge policy into a
     * SCIM 409 uniqueness error instead of a 500.
     */
    private function provision(string $directoryId, ScimUser $scim): DirectoryUser|ScimOutcome
    {
        try {
            return $this->sync->provisionUser($directoryId, $scim);
        } catch (AccountExistsForEmail) {
            return ScimOutcome::error(409, 'A user with this email already exists on the platform.', 'uniqueness');
        } catch (DirectoryUserNameTaken) {
            return ScimOutcome::error(409, 'A user with this userName already exists in this directory.', 'uniqueness');
        }
    }

    private function notFound(): ScimOutcome
    {
        return ScimOutcome::error(404, 'User not found.');
    }
}
