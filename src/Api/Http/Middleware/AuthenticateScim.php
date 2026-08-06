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
            // RFC 6750 §3 (and RFC 7235 §3.1) make the challenge mandatory on a 401:
            // "If the protected resource request ... included an access token and
            // failed authentication, the resource server ... SHOULD include the
            // 'WWW-Authenticate' response header field". ServiceProviderConfig
            // advertises `oauthbearertoken`, so a 401 with no challenge told a
            // connector nothing about WHICH scheme it had failed — several report it
            // as an unclassified transport error rather than "re-authenticate".
            return new JsonResponse([
                'schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'],
                'status' => '401',
                'detail' => 'Invalid or missing bearer token.',
            ], 401, ['WWW-Authenticate' => 'Bearer realm="SCIM"']);
        }

        $request->attributes->set('scim_directory', $directory);

        return $next($request);
    }
}
