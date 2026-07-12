<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Cbox\Id\Api\Support\ScimGroupMapper;
use Cbox\Id\Api\Support\ScimMapper;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\Models\DirectoryUser;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * SCIM 2.0 `/Groups` endpoint (RFC 7643 §4.2 / RFC 7644). Supports the group
 * lifecycle IdPs push — create, list (filtered), read, PUT replace, PATCH
 * membership add/remove/replace, and delete — scoped to the authenticated
 * directory. Membership references {@see DirectoryUser} resources by id.
 */
final class GroupController
{
    private const MAX_PAGE = 200;

    public function index(Request $request): JsonResponse
    {
        $directory = $this->directory($request);
        $query = DirectoryGroup::query()->where('directory_id', $directory->id);

        $filterExpression = $request->string('filter')->toString();
        if ($filterExpression !== '') {
            // Groups are overwhelmingly filtered by `displayName eq "x"` (the
            // membership-sync existence check). Parse just that.
            if (preg_match('/^displayName\s+eq\s+"([^"]*)"$/i', trim($filterExpression), $m) !== 1) {
                return $this->error('400', 'Unsupported filter.', 'invalidFilter');
            }

            $query->where('display_name', $m[1]);
        }

        $total = (clone $query)->count();
        $startIndex = max(1, (int) $request->integer('startIndex', 1));
        $count = min(self::MAX_PAGE, max(0, (int) $request->integer('count', self::MAX_PAGE)));

        $groups = $query->with('members')->orderBy('id')->offset($startIndex - 1)->limit($count)->get();
        $resources = array_values($groups->map(ScimGroupMapper::toResource(...))->all());

        return new JsonResponse(ScimMapper::listResponse($resources, $total, $startIndex, count($resources)));
    }

    public function store(Request $request): JsonResponse
    {
        $directory = $this->directory($request);
        $body = $this->body($request);

        $displayName = ScimGroupMapper::displayName($body);
        if ($displayName === null) {
            return $this->error('400', 'displayName is required.', 'invalidValue');
        }

        $group = DirectoryGroup::query()->create([
            'directory_id' => $directory->id,
            'display_name' => $displayName,
            'external_id' => ScimGroupMapper::externalId($body),
        ]);

        $group->members()->sync($this->resolveMembers($directory, ScimGroupMapper::memberIds($body)));

        return new JsonResponse(ScimGroupMapper::toResource($group->load('members')), 201);
    }

    public function show(Request $request, string $id): JsonResponse
    {
        $group = $this->find($this->directory($request), $id);

        return $group === null ? $this->notFound() : new JsonResponse(ScimGroupMapper::toResource($group->load('members')));
    }

    public function replace(Request $request, string $id): JsonResponse
    {
        $directory = $this->directory($request);
        $group = $this->find($directory, $id);

        if ($group === null) {
            return $this->notFound();
        }

        $body = $this->body($request);
        $displayName = ScimGroupMapper::displayName($body);

        $group->forceFill(array_filter([
            'display_name' => $displayName,
            'external_id' => ScimGroupMapper::externalId($body),
        ], static fn (mixed $v): bool => $v !== null))->save();

        // PUT is a full replace: membership becomes exactly the supplied set.
        $group->members()->sync($this->resolveMembers($directory, ScimGroupMapper::memberIds($body)));

        return new JsonResponse(ScimGroupMapper::toResource($group->load('members')));
    }

    public function patch(Request $request, string $id): JsonResponse
    {
        $directory = $this->directory($request);
        $group = $this->find($directory, $id);

        if ($group === null) {
            return $this->notFound();
        }

        $operations = $this->body($request)['Operations'] ?? [];

        if (is_array($operations)) {
            foreach ($operations as $operation) {
                if (is_array($operation)) {
                    $this->applyOperation($directory, $group, $operation);
                }
            }
        }

        return new JsonResponse(ScimGroupMapper::toResource($group->load('members')));
    }

    public function destroy(Request $request, string $id): Response
    {
        $directory = $this->directory($request);
        $group = $this->find($directory, $id);

        if ($group !== null) {
            $group->members()->detach();
            $group->delete();
        }

        return response()->noContent();
    }

    /**
     * Apply one SCIM PATCH operation (add/remove/replace) to the group.
     *
     * @param  array<array-key, mixed>  $operation
     */
    private function applyOperation(Directory $directory, DirectoryGroup $group, array $operation): void
    {
        $op = strtolower(is_string($operation['op'] ?? null) ? $operation['op'] : '');
        $path = is_string($operation['path'] ?? null) ? $operation['path'] : '';
        $value = $operation['value'] ?? null;

        // Rename: replace with a displayName in the value (path or pathless).
        if ($op === 'replace' && is_array($value) && isset($value['displayName']) && is_string($value['displayName'])) {
            $group->forceFill(['display_name' => $value['displayName']])->save();

            return;
        }

        if ($op === 'replace' && $path === 'displayName' && is_string($value)) {
            $group->forceFill(['display_name' => $value])->save();

            return;
        }

        if (! str_starts_with($path, 'members') && $path !== '') {
            return;
        }

        match ($op) {
            'add' => $group->members()->syncWithoutDetaching($this->resolveMembers($directory, $this->valueIds($value))),
            'replace' => $group->members()->sync($this->resolveMembers($directory, $this->valueIds($value))),
            'remove' => $this->removeMembers($directory, $group, $path, $value),
            default => null,
        };
    }

    private function removeMembers(Directory $directory, DirectoryGroup $group, string $path, mixed $value): void
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

        $group->members()->detach($this->resolveMembers($directory, $ids));
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
    private function resolveMembers(Directory $directory, array $ids): array
    {
        if ($ids === []) {
            return [];
        }

        $found = DirectoryUser::query()
            ->where('directory_id', $directory->id)
            ->whereIn('id', $ids)
            ->pluck('id')
            ->all();

        return array_values(array_filter($found, 'is_string'));
    }

    private function find(Directory $directory, string $id): ?DirectoryGroup
    {
        return DirectoryGroup::query()->where('directory_id', $directory->id)->whereKey($id)->first();
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
