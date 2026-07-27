<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Illuminate\Http\JsonResponse;

/**
 * SCIM 2.0 discovery endpoints (RFC 7644 §4): ServiceProviderConfig, ResourceTypes,
 * and Schemas. Identity providers (Okta, Entra) probe these during connector setup
 * to learn what the server supports, so publishing them removes setup friction and
 * mis-detection.
 */
class DiscoveryController
{
    /** RFC 7643 §4.3 Enterprise User extension schema URN. */
    private const ENTERPRISE_URN = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

    public function serviceProviderConfig(): JsonResponse
    {
        return $this->scim(array_filter([
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
            // OPTIONAL in RFC 7643 §5, and omitted unless the host actually publishes
            // something. This used to hard-code `<app>/docs`, a route this package does
            // not register and most hosts do not either — so a connector that surfaces
            // the link during setup (Okta shows it) sent the operator to a 404. An
            // absent optional field is correct; a present broken one is a promise the
            // deployment cannot keep.
            'documentationUri' => $this->documentationUri(),
            'patch' => ['supported' => true],
            'bulk' => ['supported' => false, 'maxOperations' => 0, 'maxPayloadSize' => 0],
            'filter' => ['supported' => true, 'maxResults' => 200],
            'changePassword' => ['supported' => false],
            'sort' => ['supported' => false],
            'etag' => ['supported' => false],
            'authenticationSchemes' => [[
                'type' => 'oauthbearertoken',
                'name' => 'OAuth Bearer Token',
                'description' => 'Authentication via the directory bearer token.',
                'primary' => true,
            ]],
            'meta' => ['resourceType' => 'ServiceProviderConfig'],
        ], static fn (mixed $value): bool => $value !== null));
    }

    /**
     * The host's SCIM help page, or null to omit the field.
     *
     * Filtered on `!== null` rather than a bare array_filter, so a future `false` or
     * `0` in this document cannot be silently dropped from a protocol response.
     */
    private function documentationUri(): ?string
    {
        $uri = config('cbox-id.scim.documentation_uri');

        return is_string($uri) && $uri !== '' ? $uri : null;
    }

    public function resourceTypes(): JsonResponse
    {
        $user = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
            'id' => 'User',
            'name' => 'User',
            'endpoint' => '/Users',
            'description' => 'User Account',
            'schema' => 'urn:ietf:params:scim:schemas:core:2.0:User',
            'schemaExtensions' => [[
                'schema' => self::ENTERPRISE_URN,
                'required' => false,
            ]],
            'meta' => ['resourceType' => 'ResourceType'],
        ];

        $group = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
            'id' => 'Group',
            'name' => 'Group',
            'endpoint' => '/Groups',
            'description' => 'Group',
            'schema' => 'urn:ietf:params:scim:schemas:core:2.0:Group',
            'meta' => ['resourceType' => 'ResourceType'],
        ];

        return $this->listResponse([$user, $group]);
    }

    public function schemas(): JsonResponse
    {
        return $this->listResponse([$this->userSchema(), $this->enterpriseUserSchema(), $this->groupSchema()]);
    }

    /**
     * @return array<string, mixed>
     */
    private function enterpriseUserSchema(): array
    {
        $attr = static fn (string $name, string $type): array => [
            'name' => $name,
            'type' => $type,
            'multiValued' => false,
            'required' => false,
            'caseExact' => false,
            'mutability' => 'readWrite',
            'returned' => 'default',
            'uniqueness' => 'none',
        ];

        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
            'id' => self::ENTERPRISE_URN,
            'name' => 'EnterpriseUser',
            'description' => 'Enterprise User',
            'attributes' => [
                $attr('employeeNumber', 'string'),
                $attr('costCenter', 'string'),
                $attr('organization', 'string'),
                $attr('division', 'string'),
                $attr('department', 'string'),
                [
                    'name' => 'manager', 'type' => 'complex', 'multiValued' => false,
                    'required' => false, 'mutability' => 'readWrite', 'returned' => 'default',
                    'subAttributes' => [
                        $attr('value', 'string'),
                        $attr('$ref', 'reference'),
                        ['name' => 'displayName', 'type' => 'string', 'multiValued' => false,
                            'required' => false, 'caseExact' => false, 'mutability' => 'readOnly',
                            'returned' => 'default', 'uniqueness' => 'none'],
                    ],
                ],
            ],
            'meta' => ['resourceType' => 'Schema'],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function groupSchema(): array
    {
        $sub = static fn (string $name, string $type, string $mutability = 'immutable'): array => [
            'name' => $name,
            'type' => $type,
            'multiValued' => false,
            'required' => false,
            'caseExact' => false,
            'mutability' => $mutability,
            'returned' => 'default',
            'uniqueness' => 'none',
        ];

        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
            'id' => 'urn:ietf:params:scim:schemas:core:2.0:Group',
            'name' => 'Group',
            'description' => 'Group',
            'attributes' => [
                [
                    'name' => 'displayName', 'type' => 'string', 'multiValued' => false,
                    'required' => true, 'caseExact' => false, 'mutability' => 'readWrite',
                    'returned' => 'default', 'uniqueness' => 'none',
                ],
                [
                    'name' => 'members', 'type' => 'complex', 'multiValued' => true,
                    'required' => false, 'mutability' => 'readWrite',
                    // RFC 7643 §7 `returned: "request"` — returned only when the client
                    // asks. That is what the code actually implements on a LISTING (see
                    // ScimAttributeSelection); declaring "default" made /Schemas
                    // contradict the server's own behaviour, and a schema an IdP cannot
                    // trust is worse than one that admits a limitation.
                    'returned' => 'request',
                    // Declared, not just typed `complex`: Okta's schema importer treats
                    // a complex attribute with no subAttributes as unmappable, so the
                    // whole `members` attribute silently vanished from the profile.
                    'subAttributes' => [
                        $sub('value', 'string'),
                        $sub('$ref', 'reference'),
                        $sub('type', 'string'),
                        $sub('display', 'string', 'readOnly'),
                    ],
                ],
            ],
            'meta' => ['resourceType' => 'Schema'],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function userSchema(): array
    {
        // `$returned` is not decoration. RFC 7643 §7 defines `never` as "the attribute
        // is never returned", and several sub-attributes below are exactly that: the
        // mapper ACCEPTS them on write (see ScimMapper::isTolerated()) but keeps
        // nothing, so declaring them `default` promised an admin a round-trip that
        // never happens — they map the field, import, and every value comes back blank.
        $attr = static fn (string $name, string $type, bool $required = false, string $returned = 'default'): array => [
            'name' => $name,
            'type' => $type,
            'multiValued' => false,
            'required' => $required,
            'caseExact' => false,
            'mutability' => 'readWrite',
            'returned' => $returned,
            'uniqueness' => $name === 'userName' ? 'server' : 'none',
        ];

        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
            'id' => 'urn:ietf:params:scim:schemas:core:2.0:User',
            'name' => 'User',
            'description' => 'User Account',
            // The declaration must cover everything the mapper accepts and returns. It
            // used to stop at four scalars while `name` and `emails` were fully
            // supported on the wire, so an admin running Okta's "Import Schema" got a
            // four-attribute profile and had no way to map email or first/last name —
            // the two attributes provisioning is least useful without.
            'attributes' => [
                $attr('userName', 'string', true),
                $attr('externalId', 'string'),
                [
                    'name' => 'name', 'type' => 'complex', 'multiValued' => false,
                    'required' => false, 'mutability' => 'readWrite', 'returned' => 'default',
                    'subAttributes' => [
                        $attr('formatted', 'string'),
                        $attr('familyName', 'string'),
                        $attr('givenName', 'string'),
                        // Accepted and discarded — never read back. See $attr above.
                        $attr('middleName', 'string', false, 'never'),
                        $attr('honorificPrefix', 'string', false, 'never'),
                        $attr('honorificSuffix', 'string', false, 'never'),
                    ],
                ],
                $attr('displayName', 'string'),
                [
                    'name' => 'emails', 'type' => 'complex', 'multiValued' => true,
                    'required' => false, 'mutability' => 'readWrite', 'returned' => 'default',
                    'subAttributes' => [
                        $attr('value', 'string'),
                        // The platform keeps ONE address and emits it as the primary; a
                        // per-address display label and type are read on write and then
                        // dropped, so they are never returned.
                        $attr('display', 'string', false, 'never'),
                        $attr('type', 'string', false, 'never'),
                        $attr('primary', 'boolean'),
                    ],
                ],
                $attr('active', 'boolean'),
            ],
            'meta' => ['resourceType' => 'Schema'],
        ];
    }

    /**
     * @param  list<array<string, mixed>>  $resources
     */
    private function listResponse(array $resources): JsonResponse
    {
        return $this->scim([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults' => count($resources),
            'itemsPerPage' => count($resources),
            'startIndex' => 1,
            'Resources' => $resources,
        ]);
    }

    /**
     * @param  array<string, mixed>  $body
     */
    private function scim(array $body): JsonResponse
    {
        return new JsonResponse($body, 200, ['Content-Type' => 'application/scim+json']);
    }
}
