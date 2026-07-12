<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ServerMetadata;
use Illuminate\Http\JsonResponse;

/**
 * `GET /.well-known/openid-configuration` — OIDC discovery document.
 */
final class DiscoveryController
{
    public function __invoke(): JsonResponse
    {
        return response()->json(ServerMetadata::document());
    }
}
