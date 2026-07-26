<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Cbox\Id\Api\Exceptions\InvalidScimRequest;
use Cbox\Id\Api\Support\ScimAttributeSelection;
use Cbox\Id\Api\Support\ScimGroupMapper;
use Cbox\Id\Api\Support\ScimMapper;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Exceptions\UnsupportedGroupPatch;
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
class GroupController extends ScimController
{
    public function __construct(private readonly DirectoryGroups $groups) {}

    public function index(Request $request): JsonResponse
    {
        // Membership is off by default in a LISTING and loaded only when the client
        // asks (`?attributes=members`) — a page of 200 enterprise groups otherwise
        // serializes every member of every one of them. See ScimAttributeSelection.
        $withMembers = ScimAttributeSelection::fromRequest($request)->includeMembersInListing();

        try {
            $page = $this->groups->list(
                $this->directory($request),
                $request->string('filter')->toString(),
                $request->has('startIndex') ? $request->integer('startIndex') : null,
                $request->has('count') ? $request->integer('count') : null,
                $withMembers,
            );
        } catch (UnsupportedDirectoryFilter) {
            return $this->error('400', 'Unsupported filter.', 'invalidFilter');
        }

        $resources = array_values($page->resources
            ->map(static fn ($group): array => ScimGroupMapper::toResource($group, $withMembers))
            ->all());

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

        return $this->resource(ScimGroupMapper::toResource($group), 201);
    }

    public function show(Request $request, string $id): JsonResponse
    {
        $group = $this->groups->find($this->directory($request), $id);

        // Reading ONE group returns its membership by default — asking for a single
        // group is how a client asks for its members — unless it was excluded.
        return $group === null ? $this->notFound() : $this->resource(ScimGroupMapper::toResource(
            $group,
            ScimAttributeSelection::fromRequest($request)->includeMembers(),
        ));
    }

    public function replace(Request $request, string $id): JsonResponse
    {
        $directory = $this->directory($request);
        $group = $this->groups->find($directory, $id);

        if ($group === null) {
            return $this->notFound();
        }

        $body = $this->body($request);

        // PUT is a full replacement (RFC 7644 §3.5.1) and `displayName` is the sole
        // required Group attribute (RFC 7643 §4.2) — a PUT without it is invalid, not
        // a silent no-change.
        $displayName = ScimGroupMapper::displayName($body);
        if ($displayName === null) {
            return $this->error('400', 'displayName is required.', 'invalidValue');
        }

        $group = $this->groups->replace(
            $group,
            $displayName,
            ScimGroupMapper::externalId($body),
            ScimGroupMapper::memberIds($body),
        );

        return $this->resource(ScimGroupMapper::toResource($group));
    }

    public function patch(Request $request, string $id): JsonResponse
    {
        $directory = $this->directory($request);
        $group = $this->groups->find($directory, $id);

        if ($group === null) {
            return $this->notFound();
        }

        try {
            // A missing or misspelled `Operations` used to degrade to `[]` and answer
            // 200 with the untouched group — the IdP then recorded the membership edit
            // as applied and never sent it again. A merely lower-cased `operations` is
            // legal SCIM (RFC 7643 §2.1) and is matched, not refused.
            $group = $this->groups->applyPatch($group, $this->operations($request));
        } catch (InvalidScimRequest|UnsupportedGroupPatch $e) {
            return $this->error('400', $e->getMessage(), $e->scimType);
        }

        return $this->resource(ScimGroupMapper::toResource($group));
    }

    public function destroy(Request $request, string $id): Response|JsonResponse
    {
        $group = $this->groups->find($this->directory($request), $id);

        // RFC 7644 §3.6: a delete of an unknown id is a 404, not a 204 that tells the
        // IdP a group it never had is now gone.
        if ($group === null) {
            return $this->notFound();
        }

        $this->groups->delete($group);

        return response()->noContent();
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
}
