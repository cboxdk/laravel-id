<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Middleware;

use Cbox\Id\Directory\Contracts\Directories;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authenticates a SCIM request by its directory bearer token and stashes the
 * resolved directory on the request.
 */
class AuthenticateScim
{
    public function __construct(private readonly Directories $directories) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();
        $directory = $token !== null ? $this->directories->authenticate($token) : null;

        if ($directory === null) {
            return new JsonResponse([
                'schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'],
                'status' => '401',
                'detail' => 'Invalid or missing bearer token.',
            ], 401);
        }

        $request->attributes->set('scim_directory', $directory);

        return $next($request);
    }
}
