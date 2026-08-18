<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Scim\ScimSchema;

/**
 * Maps between the SCIM 2.0 Group representation (RFC 7643 §4.2) and the
 * {@see DirectoryGroup} model.
 */
class ScimGroupMapper
{
    public const SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';

    /**
     * @param  bool  $includeMembers  when false the `members` attribute is omitted
     *                                entirely rather than emitted empty — an empty
     *                                array would tell the client the group has no
     *                                members, which is a different (and wrong) fact.
     *                                See {@see ScimAttributeSelection}.
     * @return array<string, mixed>
     */
    public static function toResource(DirectoryGroup $group, bool $includeMembers = true): array
    {
        $resource = [
            'schemas' => [self::SCHEMA],
            'id' => $group->id,
            'displayName' => $group->display_name,
            // Same reason as the User resource: without created/lastModified a
            // connector cannot ask for "what changed since", so every group sync is a
            // full sweep — and the location is the absolute URI RFC 7643 §3.1 asks for,
            // matching the response's Content-Location (RFC 7644 §3.1).
            'meta' => ScimSchema::meta(
                'Group',
                self::location($group->id),
                $group->created_at,
                $group->updated_at,
            ),
        ];

        if ($includeMembers) {
            $members = $group->members->map(static fn ($user): array => [
                'value' => $user->id,
                'display' => is_string($user->resource['userName'] ?? null) ? $user->resource['userName'] : $user->id,
            ])->all();

            $resource['members'] = array_values($members);
        }

        if ($group->external_id !== null) {
            $resource['externalId'] = $group->external_id;
        }

        return $resource;
    }

    /**
     * The absolute URI of a Group resource — `meta.location` and `Content-Location` both.
     */
    public static function location(string $id): string
    {
        return rtrim((string) url('/'), '/').'/scim/v2/Groups/'.$id;
    }

    /**
     * The member resource-ids referenced in a request body's `members` array.
     *
     * @param  array<string, mixed>  $body
     * @return list<string>
     */
    public static function memberIds(array $body): array
    {
        $members = self::attribute($body, 'members');

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
     * A top-level attribute, matched without regard to case (RFC 7643 §2.1).
     *
     * @param  array<string, mixed>  $body
     */
    private static function attribute(array $body, string $name): mixed
    {
        if (array_key_exists($name, $body)) {
            return $body[$name];
        }

        $needle = strtolower($name);

        foreach ($body as $key => $value) {
            if (strtolower((string) $key) === $needle) {
                return $value;
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $body
     */
    public static function displayName(array $body): ?string
    {
        // Case-insensitive, per RFC 7643 §2.1 — a provisioner sending `displayname` had
        // its group create refused as "displayName is required". See ScimAttributes.
        $name = self::attribute($body, 'displayName');

        return is_string($name) && $name !== '' ? $name : null;
    }

    /**
     * @param  array<string, mixed>  $body
     */
    public static function externalId(array $body): ?string
    {
        $external = self::attribute($body, 'externalId');

        return is_string($external) && $external !== '' ? $external : null;
    }
}
