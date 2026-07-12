<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Illuminate\Http\JsonResponse;

/**
 * `GET /up` — liveness probe used by deployments and the DAST pipeline.
 */
final class HealthController
{
    public function __invoke(): JsonResponse
    {
        return response()->json(['status' => 'ok']);
    }
}
