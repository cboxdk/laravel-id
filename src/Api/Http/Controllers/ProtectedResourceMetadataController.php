<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ServerMetadata;
use Illuminate\Http\JsonResponse;

/**
 * `GET /.well-known/oauth-protected-resource` — OAuth 2.0 Protected Resource
 * Metadata (RFC 9728). The current MCP authorization spec uses this so an MCP
 * client, on receiving a 401 from a resource server, can discover which
 * authorization server issues tokens for it.
 */
class ProtectedResourceMetadataController
{
    public function __invoke(): JsonResponse
    {
        $issuer = ServerMetadata::issuer();

        return response()->json([
            'resource' => $issuer,
            'authorization_servers' => [$issuer],
            'scopes_supported' => ['openid', 'profile', 'email', 'offline_access', 'organizations'],
            'bearer_methods_supported' => ['header'],
        ]);
    }
}
