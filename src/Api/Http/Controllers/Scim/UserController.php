<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Cbox\Id\Api\Exceptions\UnsupportedScimPath;
use Cbox\Id\Api\Support\ScimMapper;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Contracts\DirectoryUsers;
use Cbox\Id\Directory\Exceptions\DirectoryUserNameTaken;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Identity\Exceptions\AccountExistsForEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * SCIM 2.0 `/Users` endpoint. Provisioning maps onto the Directory module, which
 * links the local user and — on deactivation/delete — revokes sessions instantly.
 *
 * Covers the full Okta/Entra lifecycle: filtered list, create, read, PATCH
 * (active + core attributes), PUT (full replace), and delete. The controller only
 * validates and maps SCIM; the directory read/query and provisioning is delegated
 * to the {@see DirectoryUsers} and {@see DirectorySync} contracts.
 */
class UserController
{
    public function __construct(
        private readonly DirectoryUsers $users,
        private readonly DirectorySync $sync,
    ) {}

    public function index(Request $request): JsonResponse
    {
        try {
            $page = $this->users->list(
                $this->directory($request),
                $request->string('filter')->toString(),
                $request->has('startIndex') ? $request->integer('startIndex') : null,
                $request->has('count') ? $request->integer('count') : null,
            );
        } catch (UnsupportedDirectoryFilter) {
            return $this->error('400', 'Unsupported filter.', 'invalidFilter');
        }

        $resources = array_values($page->resources->map(ScimMapper::toResource(...))->all());

        return new JsonResponse(ScimMapper::listResponse($resources, $page->total, $page->startIndex, count($resources)));
    }

    public function store(Request $request): JsonResponse
    {
        $directory = $this->directory($request);

        // userName is REQUIRED (RFC 7643 §4.1.1). Without this an empty/absent userName
        // provisioned a 201 with a blank name — a resource the IdP can't address by
        // filter. Refuse at the edge with the SCIM-typed error.
        if ($request->string('userName')->toString() === '') {
            return $this->error('400', 'userName is required.', 'invalidValue');
        }

        $result = $this->provision($directory->id, ScimMapper::fromRequest($request));

        return $result instanceof JsonResponse
            ? $result
            : new JsonResponse(ScimMapper::toResource($result), 201);
    }

    public function replace(Request $request, string $id): JsonResponse
    {
        $directory = $this->directory($request);
        $target = $this->users->find($directory, $id);

        if ($target === null) {
            return $this->notFound();
        }

        // A full replace must still carry the required userName (RFC 7643 §4.1.1).
        if ($request->string('userName')->toString() === '') {
            return $this->error('400', 'userName is required.', 'invalidValue');
        }

        // The URL identifies the resource; provisioning keys by externalId. A body
        // whose externalId names a DIFFERENT resource must not be honored — otherwise
        // `PUT /Users/A` with `externalId=B` would mutate/create B and leave A intact
        // (an IDOR). Bind the replace to the located row: reject an explicit mismatch.
        $bodyExternalId = $request->string('externalId')->toString();
        if ($bodyExternalId !== '' && $bodyExternalId !== $target->external_id) {
            return $this->error('400', 'externalId does not match the target resource.', 'mutability');
        }

        // Full replace (PUT): re-provision from the submitted resource, PINNING the
        // externalId to the URL-located row. When the body omits externalId, the mapper
        // would otherwise fall back to `userName` and re-key the write to another row —
        // so `PUT /Users/A` with `{userName: "B"}` would create/overwrite B and leave A
        // untouched. Passing $target->external_id makes the URL the sole identity.
        $result = $this->provision($directory->id, ScimMapper::fromRequest($request, $target->external_id));

        return $result instanceof JsonResponse
            ? $result
            : new JsonResponse(ScimMapper::toResource($result));
    }

    public function show(Request $request, string $id): JsonResponse
    {
        $directoryUser = $this->users->find($this->directory($request), $id);

        return $directoryUser === null
            ? $this->notFound()
            : new JsonResponse(ScimMapper::toResource($directoryUser));
    }

    public function patch(Request $request, string $id): JsonResponse
    {
        $directory = $this->directory($request);
        $directoryUser = $this->users->find($directory, $id);

        if ($directoryUser === null) {
            return $this->notFound();
        }

        // Apply the PATCH operations onto the current resource and re-provision.
        // Re-provisioning with active=false deactivates: drops membership and
        // revokes sessions immediately.
        try {
            $patched = ScimMapper::applyPatch($directoryUser, $request);
        } catch (UnsupportedScimPath $e) {
            // RFC 7644 §3.5.2: an unmatched target is an error. Answering 200 would make
            // the IdP record a write that never happened and never retry it.
            return $this->error('400', $e->getMessage(), 'invalidPath');
        }

        $result = $this->provision($directory->id, $patched);

        return $result instanceof JsonResponse
            ? $result
            : new JsonResponse(ScimMapper::toResource($result));
    }

    public function destroy(Request $request, string $id): Response
    {
        $directory = $this->directory($request);
        $directoryUser = $this->users->find($directory, $id);

        if ($directoryUser !== null) {
            $this->sync->deprovisionUser($directory->id, $directoryUser->external_id);
        }

        return response()->noContent();
    }

    /**
     * Provision a user, translating the platform's no-silent-merge policy into a
     * SCIM 409 uniqueness error instead of a 500.
     */
    private function provision(string $directoryId, ScimUser $scim): DirectoryUser|JsonResponse
    {
        try {
            return $this->sync->provisionUser($directoryId, $scim);
        } catch (AccountExistsForEmail) {
            return $this->error('409', 'A user with this email already exists on the platform.', 'uniqueness');
        } catch (DirectoryUserNameTaken) {
            return $this->error('409', 'A user with this userName already exists in this directory.', 'uniqueness');
        }
    }

    private function directory(Request $request): Directory
    {
        $directory = $request->attributes->get('scim_directory');

        if (! $directory instanceof Directory) {
            abort(401);
        }

        return $directory;
    }

    private function notFound(): JsonResponse
    {
        return $this->error('404', 'User not found.');
    }

    private function error(string $status, string $detail, ?string $scimType = null): JsonResponse
    {
        $body = [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'],
            'status' => $status,
            'detail' => $detail,
        ];

        if ($scimType !== null) {
            $body['scimType'] = $scimType;
        }

        return new JsonResponse($body, (int) $status);
    }
}
