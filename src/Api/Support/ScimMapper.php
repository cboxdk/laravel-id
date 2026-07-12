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

        return new ScimUser(
            externalId: $externalId,
            userName: $userName,
            email: $email,
            displayName: $displayName,
            active: $request->boolean('active', true),
            raw: ['userName' => $userName, 'externalId' => $externalId],
        );
    }

    /**
     * @return array<string, mixed>
     */
    public static function toResource(DirectoryUser $directoryUser): array
    {
        $resource = $directoryUser->resource;
        $userName = is_string($resource['userName'] ?? null) ? $resource['userName'] : '';

        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'id' => $directoryUser->id,
            'externalId' => $directoryUser->external_id,
            'userName' => $userName,
            'active' => $directoryUser->active,
            'meta' => [
                'resourceType' => 'User',
                'location' => '/scim/v2/Users/'.$directoryUser->id,
            ],
        ];
    }

    /**
     * Extract the `active` flag from a SCIM PATCH request (the common
     * deprovision operation), tolerating both `path` and nested `value` shapes.
     */
    public static function activeFromPatch(Request $request): ?bool
    {
        $operations = $request->input('Operations');

        if (! is_array($operations)) {
            return null;
        }

        foreach ($operations as $operation) {
            if (! is_array($operation)) {
                continue;
            }

            $path = $operation['path'] ?? null;
            $value = $operation['value'] ?? null;

            if ($path === 'active') {
                return filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
            }

            if (is_array($value) && array_key_exists('active', $value)) {
                return filter_var($value['active'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
            }
        }

        return null;
    }
}
