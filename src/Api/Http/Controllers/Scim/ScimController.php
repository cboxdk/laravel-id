<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Cbox\Id\Api\Exceptions\InvalidScimRequest;
use Cbox\Id\Api\Http\Middleware\AuthenticateScim;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Scim\Enums\ScimPatchOp;
use Cbox\Id\Scim\ScimSchema;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * The plumbing every SCIM endpoint shares: resolving the authenticated directory,
 * framing errors in the RFC 7644 §3.12 Error envelope, and validating the one part
 * of a PATCH body the RFC makes mandatory.
 *
 * It lives in a base class so no endpoint can answer OUTSIDE the envelope. Okta and
 * Entra parse `application/scim+json` bodies against the Error schema; a bare
 * `{"message": "..."}` is a parse failure to them, which they surface as an opaque
 * connector fault rather than the readable reason the server actually had.
 */
abstract class ScimController
{
    /**
     * The directory the bearer token authenticated, as stashed by
     * {@see AuthenticateScim}.
     */
    protected function directory(Request $request): Directory
    {
        $directory = $request->attributes->get('scim_directory');

        if (! $directory instanceof Directory) {
            // Unreachable behind AuthenticateScim, but this used to be `abort(401)`,
            // which renders Laravel's generic body and escapes the SCIM error schema.
            // Throwing the framed response keeps the guard defensive AND on-protocol —
            // including the RFC 6750 §3 challenge the middleware's own 401 carries.
            $response = $this->error('401', 'Invalid or missing bearer token.');
            $response->headers->set('WWW-Authenticate', 'Bearer realm="SCIM"');

            throw new HttpResponseException($response);
        }

        return $directory;
    }

    /**
     * The PATCH request's `Operations` (RFC 7644 §3.5.2).
     *
     * §3.5.2 makes the member mandatory and defines it as "an array of one or more
     * PATCH operations". Both endpoints used to degrade anything else to `[]` and then
     * answer 200 with the full, unchanged resource — so a connector that sent
     * lower-case `operations`, or a proxy that normalized the key, had its
     * `active:false` push recorded as applied and never retried it.
     *
     * The lookup is CASE-INSENSITIVE, because RFC 7643 §2.1 says so without exception:
     * "Attribute names are case insensitive". A body spelling `operations` is legal
     * SCIM, so refusing it swapped one silent-success bug for a hard 400 on a request
     * the server understood perfectly well. Note this folds the top-level KEY only —
     * the `op` VALUES are folded where they are parsed
     * ({@see ScimPatchOp::tryParse()}).
     *
     * @return list<array<array-key, mixed>>
     *
     * @throws InvalidScimRequest
     */
    protected function operations(Request $request): array
    {
        $operations = array_change_key_case($request->all(), CASE_LOWER)['operations'] ?? null;

        if (! is_array($operations) || $operations === []) {
            throw InvalidScimRequest::missingOperations();
        }

        $parsed = [];

        foreach ($operations as $operation) {
            if (! is_array($operation)) {
                throw InvalidScimRequest::notAnOperation();
            }

            $parsed[] = $operation;
        }

        return $parsed;
    }

    /**
     * A single-resource response.
     *
     * RFC 7644 §3.1 lists `Content-Location` among the response headers and requires it
     * to have "the same value as the 'meta.location' attribute" — so a client that
     * re-reads a resource from either one lands on the same URI. The server sent
     * neither an absolute location nor the header at all, which left Okta's
     * post-write re-read resolving a bare path against its own base URL.
     *
     * A 201 additionally carries `Location` (RFC 7644 §3.3).
     *
     * @param  array<string, mixed>  $resource
     */
    protected function resource(array $resource, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($resource, $status);

        $meta = $resource['meta'] ?? null;
        $location = is_array($meta) ? ($meta['location'] ?? null) : null;

        if (is_string($location) && $location !== '') {
            $response->headers->set('Content-Location', $location);

            if ($status === 201) {
                $response->headers->set('Location', $location);
            }
        }

        return $response;
    }

    /**
     * A SCIM Error response (RFC 7644 §3.12).
     */
    protected function error(string $status, string $detail, ?string $scimType = null): JsonResponse
    {
        return new JsonResponse(ScimSchema::error($status, $detail, $scimType), (int) $status);
    }
}
