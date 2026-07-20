<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * SCIM 2.0 defines its own media type, `application/scim+json` (RFC 7644 §3.1).
 * Setting it on every SCIM response here — in one place — keeps each thin
 * controller from repeating the header, and guarantees error bodies carry it too.
 * Only JSON responses are retagged; a 204 No Content (a successful DELETE) keeps
 * its empty body and no content type.
 */
class ScimContentType
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if ($response->getContent() !== '' && $response->getContent() !== false) {
            $response->headers->set('Content-Type', 'application/scim+json');
        }

        return $response;
    }
}
