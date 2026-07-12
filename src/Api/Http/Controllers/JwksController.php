<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Illuminate\Http\JsonResponse;

/**
 * `GET /.well-known/jwks.json` — the public JWK Set for verifying tokens.
 */
final class JwksController
{
    public function __invoke(KeyManager $keys): JsonResponse
    {
        return response()->json($keys->jwks());
    }
}
