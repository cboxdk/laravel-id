<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Middleware;

use Cbox\Id\Scim\ScimSchema;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Makes every SCIM response speak SCIM — both its media type and, for failures, its
 * error schema.
 *
 * SCIM 2.0 defines its own media type, `application/scim+json` (RFC 7644 §3.1), and
 * its own error body (§3.12). Setting them here — in one place, on the OUTSIDE of the
 * SCIM stack — keeps each thin controller from repeating the header and, more
 * importantly, catches the failures no controller ever sees: the throttle's 429 and
 * anything else the framework renders inside the group. Those arrive as
 * `{"message": "Too Many Attempts."}` in `application/json`; Okta and Entra parse a
 * SCIM response against the Error schema, so an unparsable body reads as a fatal
 * connector fault instead of "back off and retry" — which is how a rate limit turns
 * into a quarantined provisioning job.
 *
 * A 204 No Content (a successful DELETE) keeps its empty body and no content type.
 */
class ScimContentType
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $content = $response->getContent();

        if ($content === '' || $content === false) {
            return $response;
        }

        if ($response->getStatusCode() >= 400 && ! $this->isScimError($content)) {
            $response = $this->reframe($response, $content);
        }

        $response->headers->set('Content-Type', ScimSchema::CONTENT_TYPE);

        return $response;
    }

    /**
     * Whether the body is already a SCIM Error envelope — the controllers' own errors
     * are, and must pass through with their `scimType` and detail intact.
     */
    private function isScimError(string $content): bool
    {
        $decoded = json_decode($content, true);

        if (! is_array($decoded)) {
            return false;
        }

        $schemas = $decoded['schemas'] ?? null;

        return is_array($schemas) && in_array(ScimSchema::ERROR_URN, $schemas, true);
    }

    /**
     * Re-frame a framework-rendered error as a SCIM Error, carrying the original
     * headers across — `Retry-After` above all, since that is the only thing telling
     * the IdP how long to wait instead of failing the run.
     */
    private function reframe(Response $response, string $content): Response
    {
        $status = $response->getStatusCode();
        $scim = new JsonResponse(ScimSchema::error((string) $status, $this->detail($content, $status)), $status);

        foreach ($response->headers->all() as $name => $values) {
            if (in_array(strtolower($name), ['content-type', 'content-length'], true)) {
                continue;
            }

            $carried = array_values(array_filter($values, is_string(...)));

            if ($carried !== []) {
                $scim->headers->set($name, $carried);
            }
        }

        return $scim;
    }

    /**
     * The human-readable reason, preferring the framework's own `message` so the
     * detail stays specific ("Too Many Attempts.") rather than generic.
     */
    private function detail(string $content, int $status): string
    {
        $decoded = json_decode($content, true);
        $message = is_array($decoded) ? ($decoded['message'] ?? null) : null;

        if (is_string($message) && $message !== '') {
            return $message;
        }

        return Response::$statusTexts[$status] ?? 'The request could not be completed.';
    }
}
