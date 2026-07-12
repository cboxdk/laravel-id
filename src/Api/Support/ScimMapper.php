<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Illuminate\Http\Request;

/**
 * Translates between the SCIM 2.0 User schema on the wire and the platform's
 * {@see ScimUser} value object / {@see DirectoryUser} model.
 */
final class ScimMapper
{
    public static function fromRequest(Request $request): ScimUser
    {
        $userName = $request->string('userName')->toString();
        $externalId = $request->string('externalId')->toString() ?: $userName;

        $emailRaw = $request->input('emails.0.value');
        $email = is_string($emailRaw) ? $emailRaw : null;

        $displayName = $request->string('displayName')->toString();
        if ($displayName === '') {
            $formatted = $request->input('name.formatted');
            $displayName = is_string($formatted) ? $formatted : $userName;
        }

        return self::build($externalId, $userName, $email, $displayName, $request->boolean('active', true));
    }

    /**
     * Apply a SCIM PATCH request onto an existing user, returning the updated
     * resource to re-provision. Supports both `path`-based operations and the
     * pathless "replace whole value object" form (Azure/Entra), across the
     * attributes IdPs actually patch: active, userName, displayName,
     * name.formatted and emails.
     */
    public static function applyPatch(DirectoryUser $existing, Request $request): ScimUser
    {
        $resource = $existing->resource;
        $attributes = [
            'userName' => self::str($resource['userName'] ?? null),
            'externalId' => $existing->external_id,
            'email' => self::nullableStr($resource['email'] ?? null),
            'displayName' => self::nullableStr($resource['displayName'] ?? null),
            'active' => $existing->active,
        ];

        $operations = $request->input('Operations');

        foreach (is_array($operations) ? $operations : [] as $operation) {
            if (! is_array($operation) || strtolower(self::str($operation['op'] ?? 'replace')) === 'remove') {
                continue;
            }

            $path = $operation['path'] ?? null;
            $value = $operation['value'] ?? null;

            if (is_string($path)) {
                self::setAttribute($attributes, $path, $value);
            } elseif (is_array($value)) {
                foreach ($value as $key => $nested) {
                    self::setAttribute($attributes, (string) $key, $nested);
                }
            }
        }

        return self::build(
            self::str($attributes['externalId']),
            self::str($attributes['userName']),
            self::nullableStr($attributes['email']),
            self::nullableStr($attributes['displayName']),
            (bool) $attributes['active'],
        );
    }

    /**
     * Build a SCIM ListResponse envelope.
     *
     * @param  list<array<string, mixed>>  $resources
     * @return array<string, mixed>
     */
    public static function listResponse(array $resources, int $totalResults, int $startIndex, int $itemsPerPage): array
    {
        return [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults' => $totalResults,
            'startIndex' => $startIndex,
            'itemsPerPage' => $itemsPerPage,
            'Resources' => $resources,
        ];
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private static function setAttribute(array &$attributes, string $path, mixed $value): void
    {
        match (strtolower($path)) {
            'active' => $attributes['active'] = filter_var($value, FILTER_VALIDATE_BOOLEAN),
            'username' => $attributes['userName'] = self::str($value),
            'displayname' => $attributes['displayName'] = self::str($value),
            'name.formatted' => $attributes['displayName'] = self::str($value),
            'emails', 'emails[type eq "work"].value' => $attributes['email'] = self::extractEmail($value),
            default => null,
        };
    }

    private static function extractEmail(mixed $value): ?string
    {
        if (is_string($value)) {
            return $value !== '' ? $value : null;
        }

        // emails as a list of {value: ...} — take the first usable address.
        if (is_array($value)) {
            foreach ($value as $entry) {
                if (is_array($entry) && isset($entry['value']) && is_string($entry['value'])) {
                    return $entry['value'];
                }
            }
        }

        return null;
    }

    private static function build(string $externalId, string $userName, ?string $email, ?string $displayName, bool $active): ScimUser
    {
        return new ScimUser(
            externalId: $externalId,
            userName: $userName,
            email: $email,
            displayName: $displayName,
            active: $active,
            raw: [
                'userName' => $userName,
                'externalId' => $externalId,
                'email' => $email,
                'displayName' => $displayName,
                'active' => $active,
            ],
        );
    }

    private static function str(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }

    private static function nullableStr(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return array<string, mixed>
     */
    public static function toResource(DirectoryUser $directoryUser): array
    {
        $resource = $directoryUser->resource;
        $displayName = self::nullableStr($resource['displayName'] ?? null);
        $email = self::nullableStr($resource['email'] ?? null);

        $out = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'id' => $directoryUser->id,
            'externalId' => $directoryUser->external_id,
            'userName' => self::str($resource['userName'] ?? null),
            'active' => $directoryUser->active,
            'meta' => [
                'resourceType' => 'User',
                'location' => '/scim/v2/Users/'.$directoryUser->id,
            ],
        ];

        if ($displayName !== null) {
            $out['displayName'] = $displayName;
            $out['name'] = ['formatted' => $displayName];
        }

        if ($email !== null) {
            $out['emails'] = [['value' => $email, 'primary' => true]];
        }

        return $out;
    }
}
