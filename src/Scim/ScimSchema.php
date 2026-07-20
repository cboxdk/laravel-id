<?php

declare(strict_types=1);

namespace Cbox\Id\Scim;

/**
 * Pure, transport-agnostic SCIM 2.0 schema constants and body builders — the
 * single source of truth for the URNs (RFC 7643) and message shapes (RFC 7644)
 * shared by BOTH sides of the platform's SCIM surface:
 *
 *  - the INBOUND SCIM server (`Api\Support\ScimMapper`), which receives
 *    provisioning INTO the platform, and
 *  - the OUTBOUND SCIM client (the `Provisioning` module), which pushes
 *    provisioning OUT to a downstream app's SCIM endpoint.
 *
 * This class holds only the schema vocabulary and the pure array builders that
 * are identical regardless of direction; nothing here touches HTTP, Eloquent or
 * the request lifecycle, so both the server (framing responses) and the client
 * (framing request bodies) reuse it instead of duplicating URN literals.
 */
class ScimSchema
{
    /** RFC 7643 §4.1 core User resource schema URN. */
    public const USER_URN = 'urn:ietf:params:scim:schemas:core:2.0:User';

    /** RFC 7643 §4.2 core Group resource schema URN. */
    public const GROUP_URN = 'urn:ietf:params:scim:schemas:core:2.0:Group';

    /** RFC 7643 §4.3 Enterprise User extension schema URN. */
    public const ENTERPRISE_URN = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

    /** RFC 7644 §3.5.2 PATCH request message schema URN. */
    public const PATCH_OP_URN = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

    /** RFC 7644 §3.4.2 query ListResponse message schema URN. */
    public const LIST_RESPONSE_URN = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';

    /** RFC 7644 §3.12 error message schema URN. */
    public const ERROR_URN = 'urn:ietf:params:scim:api:messages:2.0:Error';

    /** The media type every SCIM request and response body carries (RFC 7644 §3.1). */
    public const CONTENT_TYPE = 'application/scim+json';

    /**
     * Build a SCIM 2.0 `User` resource body (RFC 7643 §4.1) for a create (POST)
     * or replace (PUT), from an already-mapped attribute bag. `externalId` binds
     * the remote resource back to the platform's own user id, so a later
     * reconcile can locate it with `externalId eq "…"`.
     *
     * @param  array<string, mixed>  $attributes  mapped SCIM attributes (userName, name, emails, active, …)
     * @return array<string, mixed>
     */
    public static function userResource(string $externalId, array $attributes): array
    {
        $enterprise = self::extractEnterprise($attributes);

        // `schemas`/`externalId` lead, then the mapped attributes (which no longer
        // carry the inline `enterprise` key — extractEnterprise removed it).
        $body = [
            'schemas' => [self::USER_URN],
            'externalId' => $externalId,
        ] + $attributes;

        if ($enterprise !== []) {
            $body['schemas'][] = self::ENTERPRISE_URN;
            $body[self::ENTERPRISE_URN] = $enterprise;
        }

        return $body;
    }

    /**
     * Build a SCIM 2.0 `PatchOp` request body (RFC 7644 §3.5.2).
     *
     * @param  list<array{op: string, path?: string, value?: mixed}>  $operations
     * @return array{schemas: list<string>, Operations: list<array<string, mixed>>}
     */
    public static function patchOp(array $operations): array
    {
        return [
            'schemas' => [self::PATCH_OP_URN],
            'Operations' => $operations,
        ];
    }

    /**
     * A single `replace` PATCH operation (RFC 7644 §3.5.2.3).
     *
     * @return array{op: string, path: string, value: mixed}
     */
    public static function replace(string $path, mixed $value): array
    {
        return ['op' => 'replace', 'path' => $path, 'value' => $value];
    }

    /**
     * The `replace active` deactivation/reactivation op every IdP understands.
     *
     * @return array{op: string, path: string, value: bool}
     */
    public static function setActive(bool $active): array
    {
        return ['op' => 'replace', 'path' => 'active', 'value' => $active];
    }

    /**
     * A SCIM ListResponse envelope (RFC 7644 §3.4.2).
     *
     * @param  list<array<string, mixed>>  $resources
     * @return array<string, mixed>
     */
    public static function listResponse(array $resources, int $totalResults, int $startIndex, int $itemsPerPage): array
    {
        return [
            'schemas' => [self::LIST_RESPONSE_URN],
            'totalResults' => $totalResults,
            'startIndex' => $startIndex,
            'itemsPerPage' => $itemsPerPage,
            'Resources' => $resources,
        ];
    }

    /**
     * A SCIM error body (RFC 7644 §3.12).
     *
     * @return array<string, mixed>
     */
    public static function error(string $status, string $detail, ?string $scimType = null): array
    {
        $body = [
            'schemas' => [self::ERROR_URN],
            'status' => $status,
            'detail' => $detail,
        ];

        if ($scimType !== null) {
            $body['scimType'] = $scimType;
        }

        return $body;
    }

    /**
     * A SCIM `attr eq "value"` filter expression (RFC 7644 §3.4.2.2), with the
     * value's quotes and backslashes escaped so it cannot break out of the literal.
     */
    public static function equalityFilter(string $attribute, string $value): string
    {
        $escaped = str_replace(['\\', '"'], ['\\\\', '\\"'], $value);

        return sprintf('%s eq "%s"', $attribute, $escaped);
    }

    /**
     * Split an inline Enterprise-extension attribute (`enterprise`) out of a
     * mapped attribute bag so it can be emitted under its URN key.
     *
     * @param  array<string, mixed>  $attributes
     * @return array<string, mixed>
     */
    private static function extractEnterprise(array &$attributes): array
    {
        $enterprise = [];
        $raw = $attributes['enterprise'] ?? null;

        if (is_array($raw)) {
            foreach ($raw as $key => $value) {
                $enterprise[(string) $key] = $value;
            }
        }

        unset($attributes['enterprise'], $attributes[self::ENTERPRISE_URN]);

        return $enterprise;
    }
}
