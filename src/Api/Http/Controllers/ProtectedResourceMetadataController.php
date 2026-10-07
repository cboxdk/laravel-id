<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\OAuthServer\Contracts\ProtectedResources;
use Illuminate\Http\JsonResponse;

/**
 * OAuth 2.0 Protected Resource Metadata (RFC 9728).
 *
 * `GET /.well-known/oauth-protected-resource` describes the authorization server itself as
 * a resource (UserInfo, the decision endpoint). `GET /.well-known/oauth-protected-resource/{path}`
 * describes a resource the host declared ({@see ProtectedResources}) — RFC 9728 §3.1
 * inserts the well-known suffix between the host and the resource's path, so the document
 * for `https://h/mcp` is served at `https://h/.well-known/oauth-protected-resource/mcp`.
 * That second form is what the MCP authorization flow fetches after a 401.
 */
class ProtectedResourceMetadataController
{
    public function __construct(private readonly ProtectedResources $resources) {}

    public function __invoke(): JsonResponse
    {
        $issuer = ServerMetadata::issuer();

        return response()->json([
            'resource' => $issuer,
            'authorization_servers' => [$issuer],
            // From the resolver, not a constant of this controller's own: this list once
            // had its own copy and was one scope short — `groups`, which is exactly the
            // one a Kubernetes client asks for after reading a document that promised it.
            'scopes_supported' => $this->resources->issuerScopes(),
            'bearer_methods_supported' => ['header'],
        ]);
    }

    /**
     * RFC 9728 §3.3: the `resource` in the document must be the identifier the URL was
     * built from, which holds by construction — the lookup is by that very path. A path
     * no declared resource lives at is a 404, not the root document: answering with
     * another resource's metadata is the substitution §3.3 tells clients to reject.
     */
    public function show(string $path): JsonResponse
    {
        $resource = $this->resources->forMetadataPath('/.well-known/oauth-protected-resource/'.$path);

        if ($resource === null) {
            return response()->json(['error' => 'not_found'], 404);
        }

        return response()->json($resource->metadata(ServerMetadata::issuer()));
    }
}
