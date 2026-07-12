<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Cbox\Id\Api\Support\ScimMapper;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryUser;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * SCIM 2.0 `/Users` endpoint. Provisioning maps onto the Directory module, which
 * links the local user and — on deactivation/delete — revokes sessions instantly.
 *
 * Covered: create, read, deactivate-via-PATCH, delete (the Okta/Entra lifecycle).
 * Full PATCH operation set + `.../Users` filter queries are a follow-up.
 */
final class UserController
{
    public function __construct(private readonly DirectorySync $sync) {}

    public function store(Request $request): JsonResponse
    {
        $directory = $this->directory($request);
        $scim = ScimMapper::fromRequest($request);

        $directoryUser = $this->sync->provisionUser($directory->id, $scim);

        return new JsonResponse(ScimMapper::toResource($directoryUser), 201);
    }

    public function show(Request $request, string $id): JsonResponse
    {
        $directoryUser = $this->find($this->directory($request), $id);

        return $directoryUser === null
            ? $this->notFound()
            : new JsonResponse(ScimMapper::toResource($directoryUser));
    }

    public function patch(Request $request, string $id): JsonResponse
    {
        $directory = $this->directory($request);
        $directoryUser = $this->find($directory, $id);

        if ($directoryUser === null) {
            return $this->notFound();
        }

        if (ScimMapper::activeFromPatch($request) === false) {
            $this->sync->deprovisionUser($directory->id, $directoryUser->external_id);
        }

        return new JsonResponse(ScimMapper::toResource($this->find($directory, $id) ?? $directoryUser));
    }

    public function destroy(Request $request, string $id): Response
    {
        $directory = $this->directory($request);
        $directoryUser = $this->find($directory, $id);

        if ($directoryUser !== null) {
            $this->sync->deprovisionUser($directory->id, $directoryUser->external_id);
        }

        return response()->noContent();
    }

    private function find(Directory $directory, string $id): ?DirectoryUser
    {
        return DirectoryUser::query()
            ->where('directory_id', $directory->id)
            ->whereKey($id)
            ->first();
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
        return new JsonResponse([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'],
            'status' => '404',
            'detail' => 'User not found.',
        ], 404);
    }
}
