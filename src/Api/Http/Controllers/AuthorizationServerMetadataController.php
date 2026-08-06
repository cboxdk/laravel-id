<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ServerMetadata;
use Illuminate\Http\JsonResponse;

/**
 * `GET /.well-known/oauth-authorization-server` — OAuth 2.0 Authorization Server
 * Metadata (RFC 8414). MCP clients fetch this URL specifically (they do not
 * always fall back to the OIDC discovery document), so it is served explicitly
 * from the same metadata as the OIDC endpoint.
 */
class AuthorizationServerMetadataController
{
    public function __invoke(): JsonResponse
    {
        return response()->json(ServerMetadata::document());
    }
}
