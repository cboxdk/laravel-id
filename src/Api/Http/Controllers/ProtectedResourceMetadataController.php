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
            // From the same constant discovery reads. This list had its own copy and was
            // one scope short — `groups`, which is exactly the one a Kubernetes client
            // asks for after reading a document that promised it.
            'scopes_supported' => ServerMetadata::SCOPES_SUPPORTED,
            'bearer_methods_supported' => ['header'],
        ]);
    }
}
