<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Cbox\Id\Directory\Models\DirectoryGroup;

/**
 * Maps between the SCIM 2.0 Group representation (RFC 7643 §4.2) and the
 * {@see DirectoryGroup} model.
 */
class ScimGroupMapper
{
    public const SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';

    /**
     * @return array<string, mixed>
     */
    public static function toResource(DirectoryGroup $group): array
    {
        $members = $group->members->map(static fn ($user): array => [
            'value' => $user->id,
            'display' => is_string($user->resource['userName'] ?? null) ? $user->resource['userName'] : $user->id,
        ])->all();

        $resource = [
            'schemas' => [self::SCHEMA],
            'id' => $group->id,
            'displayName' => $group->display_name,
            'members' => array_values($members),
            'meta' => ['resourceType' => 'Group'],
        ];

        if ($group->external_id !== null) {
            $resource['externalId'] = $group->external_id;
        }

        return $resource;
    }

    /**
     * The member resource-ids referenced in a request body's `members` array.
     *
     * @param  array<string, mixed>  $body
     * @return list<string>
     */
    public static function memberIds(array $body): array
    {
        $members = $body['members'] ?? null;

        if (! is_array($members)) {
            return [];
        }

        $ids = [];

        foreach ($members as $member) {
            $value = is_array($member) ? ($member['value'] ?? null) : $member;

            if (is_string($value) && $value !== '') {
                $ids[] = $value;
            }
        }

        return array_values(array_unique($ids));
    }

    /**
     * @param  array<string, mixed>  $body
     */
    public static function displayName(array $body): ?string
    {
        $name = $body['displayName'] ?? null;

        return is_string($name) && $name !== '' ? $name : null;
    }

    /**
     * @param  array<string, mixed>  $body
     */
    public static function externalId(array $body): ?string
    {
        $external = $body['externalId'] ?? null;

        return is_string($external) && $external !== '' ? $external : null;
    }
}
