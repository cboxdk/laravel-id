<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Cbox\Id\Api\Support\ScimFilter;
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
 * Covers the full Okta/Entra lifecycle: filtered list, create, read, PATCH
 * (active + core attributes), PUT (full replace), and delete.
 */
final class UserController
{
    private const MAX_PAGE = 200;

    public function __construct(private readonly DirectorySync $sync) {}

    public function index(Request $request): JsonResponse
    {
        $directory = $this->directory($request);

        $query = DirectoryUser::query()->where('directory_id', $directory->id);

        $filterExpression = $request->string('filter')->toString();
        if ($filterExpression !== '') {
            $filter = ScimFilter::parse($filterExpression);

            if ($filter === null) {
                return $this->error('400', 'Unsupported filter.', 'invalidFilter');
            }

            $filter->apply($query);
        }

        $total = (clone $query)->count();

        $startIndex = max(1, (int) $request->integer('startIndex', 1));
        $count = min(self::MAX_PAGE, max(0, (int) $request->integer('count', self::MAX_PAGE)));

        $users = $query->orderBy('id')->offset($startIndex - 1)->limit($count)->get();
        $resources = array_values($users->map(ScimMapper::toResource(...))->all());

        return new JsonResponse(ScimMapper::listResponse($resources, $total, $startIndex, count($resources)));
    }

    public function store(Request $request): JsonResponse
    {
        $directory = $this->directory($request);
        $scim = ScimMapper::fromRequest($request);

        $directoryUser = $this->sync->provisionUser($directory->id, $scim);

        return new JsonResponse(ScimMapper::toResource($directoryUser), 201);
    }

    public function replace(Request $request, string $id): JsonResponse
    {
        $directory = $this->directory($request);
        $directoryUser = $this->find($directory, $id);

        if ($directoryUser === null) {
            return $this->notFound();
        }

        // Full replace (PUT): re-provision from the submitted resource, keeping
        // the record identified by its stored externalId.
        $scim = ScimMapper::fromRequest($request);
        $updated = $this->sync->provisionUser($directory->id, $scim);

        return new JsonResponse(ScimMapper::toResource($updated));
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

        // Apply the PATCH operations onto the current resource and re-provision.
        // Re-provisioning with active=false deactivates: drops membership and
        // revokes sessions immediately.
        $scim = ScimMapper::applyPatch($directoryUser, $request);
        $updated = $this->sync->provisionUser($directory->id, $scim);

        return new JsonResponse(ScimMapper::toResource($updated));
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
