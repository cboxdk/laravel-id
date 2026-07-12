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
final class DiscoveryController
{
    public function serviceProviderConfig(): JsonResponse
    {
        return $this->scim([
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
            'documentationUri' => rtrim((string) url('/'), '/').'/docs',
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
        ]);
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
            'meta' => ['resourceType' => 'ResourceType'],
        ];

        return $this->listResponse([$user]);
    }

    public function schemas(): JsonResponse
    {
        return $this->listResponse([$this->userSchema()]);
    }

    /**
     * @return array<string, mixed>
     */
    private function userSchema(): array
    {
        $attr = static fn (string $name, string $type, bool $required = false): array => [
            'name' => $name,
            'type' => $type,
            'multiValued' => false,
            'required' => $required,
            'caseExact' => false,
            'mutability' => 'readWrite',
            'returned' => 'default',
            'uniqueness' => $name === 'userName' ? 'server' : 'none',
        ];

        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
            'id' => 'urn:ietf:params:scim:schemas:core:2.0:User',
            'name' => 'User',
            'description' => 'User Account',
            'attributes' => [
                $attr('userName', 'string', true),
                $attr('externalId', 'string'),
                $attr('displayName', 'string'),
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
