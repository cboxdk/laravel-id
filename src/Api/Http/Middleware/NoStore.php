<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `Cache-Control: no-store` on every credential-bearing response.
 *
 * RFC 6749 §5.1 makes this a MUST on token responses, and RFC 7662 §2.2 repeats it for
 * introspection. Without it a shared forward proxy, a CDN misconfigured to cache POST
 * responses, or a browser back-button replay can serve an access token, refresh token
 * or device code to a second party.
 *
 * Applied as middleware rather than per-controller so a new endpoint on the OAuth group
 * inherits it: the previous per-response approach meant every added endpoint was one
 * forgotten line away from caching credentials.
 */
class NoStore
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }
}
