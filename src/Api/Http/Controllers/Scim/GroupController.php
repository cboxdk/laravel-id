<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Cbox\Id\Api\Support\ScimGroupMapper;
use Cbox\Id\Api\Support\ScimMapper;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Models\Directory;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * SCIM 2.0 `/Groups` endpoint (RFC 7643 §4.2 / RFC 7644). Supports the group
 * lifecycle IdPs push — create, list (filtered), read, PUT replace, PATCH
 * membership add/remove/replace, and delete — scoped to the authenticated
 * directory. The group domain (queries, PATCH semantics, membership resolution)
 * lives behind the {@see DirectoryGroups} contract; the controller validates and
 * maps SCIM only.
 */
class GroupController
{
    public function __construct(private readonly DirectoryGroups $groups) {}

    public function index(Request $request): JsonResponse
    {
        try {
            $page = $this->groups->list(
                $this->directory($request),
                $request->string('filter')->toString(),
                $request->has('startIndex') ? $request->integer('startIndex') : null,
                $request->has('count') ? $request->integer('count') : null,
            );
        } catch (UnsupportedDirectoryFilter) {
            return $this->error('400', 'Unsupported filter.', 'invalidFilter');
        }

        $resources = array_values($page->resources->map(ScimGroupMapper::toResource(...))->all());

        return new JsonResponse(ScimMapper::listResponse($resources, $page->total, $page->startIndex, count($resources)));
    }

    public function store(Request $request): JsonResponse
    {
        $directory = $this->directory($request);
        $body = $this->body($request);

        $displayName = ScimGroupMapper::displayName($body);
        if ($displayName === null) {
            return $this->error('400', 'displayName is required.', 'invalidValue');
        }

        $group = $this->groups->create(
            $directory,
            $displayName,
            ScimGroupMapper::externalId($body),
            ScimGroupMapper::memberIds($body),
        );

        return new JsonResponse(ScimGroupMapper::toResource($group), 201);
    }

    public function show(Request $request, string $id): JsonResponse
    {
        $group = $this->groups->find($this->directory($request), $id);

        return $group === null ? $this->notFound() : new JsonResponse(ScimGroupMapper::toResource($group));
    }

    public function replace(Request $request, string $id): JsonResponse
    {
        $directory = $this->directory($request);
        $group = $this->groups->find($directory, $id);

        if ($group === null) {
            return $this->notFound();
        }

        $body = $this->body($request);

        $group = $this->groups->replace(
            $group,
            ScimGroupMapper::displayName($body),
            ScimGroupMapper::externalId($body),
            ScimGroupMapper::memberIds($body),
        );

        return new JsonResponse(ScimGroupMapper::toResource($group));
    }

    public function patch(Request $request, string $id): JsonResponse
    {
        $directory = $this->directory($request);
        $group = $this->groups->find($directory, $id);

        if ($group === null) {
            return $this->notFound();
        }

        $operations = $this->body($request)['Operations'] ?? [];

        $group = $this->groups->applyPatch($group, is_array($operations) ? $operations : []);

        return new JsonResponse(ScimGroupMapper::toResource($group));
    }

    public function destroy(Request $request, string $id): Response
    {
        $group = $this->groups->find($this->directory($request), $id);

        if ($group !== null) {
            $this->groups->delete($group);
        }

        return response()->noContent();
    }

    private function directory(Request $request): Directory
    {
        $directory = $request->attributes->get('scim_directory');

        if (! $directory instanceof Directory) {
            abort(401);
        }

        return $directory;
    }

    /**
     * @return array<string, mixed>
     */
    private function body(Request $request): array
    {
        $data = $request->json()->all();
        $data = $data === [] ? $request->all() : $data;

        $normalized = [];

        foreach ($data as $key => $value) {
            $normalized[(string) $key] = $value;
        }

        return $normalized;
    }

    private function notFound(): JsonResponse
    {
        return $this->error('404', 'Group not found.');
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
