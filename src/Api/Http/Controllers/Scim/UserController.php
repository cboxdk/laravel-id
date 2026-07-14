<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Cbox\Id\Api\Support\ScimMapper;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Contracts\DirectoryUsers;
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
final class UserController
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
        $result = $this->provision($directory->id, ScimMapper::fromRequest($request));

        return $result instanceof JsonResponse
            ? $result
            : new JsonResponse(ScimMapper::toResource($result), 201);
    }

    public function replace(Request $request, string $id): JsonResponse
    {
        $directory = $this->directory($request);

        if ($this->users->find($directory, $id) === null) {
            return $this->notFound();
        }

        // Full replace (PUT): re-provision from the submitted resource, keeping
        // the record identified by its stored externalId.
        $result = $this->provision($directory->id, ScimMapper::fromRequest($request));

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
        $result = $this->provision($directory->id, ScimMapper::applyPatch($directoryUser, $request));

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
