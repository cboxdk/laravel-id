<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\ValueObjects;

/**
 * The outcome of a single outbound SCIM HTTP operation, normalized so the
 * provisioning service can reconcile without re-parsing HTTP. `transport` is true
 * when the request never produced a response (DNS/TLS/timeout/connection error),
 * which — like a 429 or a 5xx — is a TRANSIENT failure the drain should retry;
 * a 4xx (other than the specially-handled 404/409) is a PERMANENT client error.
 */
final readonly class ScimResult
{
    /**
     * @param  array<string, mixed>  $body  the parsed SCIM response body ([] on transport error)
     */
    public function __construct(
        public int $status,
        public array $body = [],
        public bool $transport = false,
    ) {}

    /**
     * @param  array<string, mixed>  $body
     */
    public static function http(int $status, array $body = []): self
    {
        return new self($status, $body);
    }

    public static function transportError(): self
    {
        return new self(0, [], true);
    }

    public function successful(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }

    /** RFC 7644 §3.3: the target already exists (uniqueness) — reconcile, don't duplicate. */
    public function conflict(): bool
    {
        return $this->status === 409;
    }

    /** The remote resource is gone — an update must recreate it. */
    public function notFound(): bool
    {
        return $this->status === 404;
    }

    /** A failure worth retrying: no response at all, rate-limited, or a server error. */
    public function transient(): bool
    {
        return $this->transport || $this->status === 429 || $this->status >= 500;
    }

    /** The remote resource id (SCIM `id`) the downstream app assigned, if present. */
    public function remoteId(): ?string
    {
        $id = $this->body['id'] ?? null;

        return is_string($id) && $id !== '' ? $id : null;
    }

    /**
     * The remote id of the resource in a filtered `GET /Users?filter=externalId eq …`
     * ListResponse whose `externalId` ACTUALLY equals `$externalId` — the safe
     * reconcile lookup for a 409.
     *
     * A well-known SCIM interop defect is a server that ignores an unknown filter
     * and returns its FULL user list with 200. Blindly taking `Resources[0].id`
     * would then durably bind an arbitrary downstream user as this subject's mirror,
     * so every later PATCH/DELETE would hit the wrong person. Guard against it: refuse
     * an ambiguous multi-result response, and require the matched resource to carry
     * the expected `externalId`. On any doubt, return null and let the operation
     * retry/dead-letter rather than adopt a wrong target.
     */
    public function resourceIdForExternalId(string $externalId): ?string
    {
        $resources = $this->body['Resources'] ?? null;

        if (! is_array($resources) || $resources === []) {
            return null;
        }

        // A correctly-filtered response has zero or one match. More than one means
        // the peer did not honor the filter — refuse rather than guess.
        $total = $this->body['totalResults'] ?? null;

        if ((is_int($total) && $total > 1) || count($resources) > 1) {
            return null;
        }

        $first = $resources[0] ?? null;

        if (! is_array($first)) {
            return null;
        }

        $matchedExternalId = $first['externalId'] ?? null;

        if (! is_string($matchedExternalId) || $matchedExternalId !== $externalId) {
            return null;
        }

        $id = $first['id'] ?? null;

        return is_string($id) && $id !== '' ? $id : null;
    }

    /**
     * A short, SECRET-FREE description of a failed response for the outbox
     * `last_error` column — the SCIM `detail`, never a header or the token.
     */
    public function errorDetail(): string
    {
        $detail = $this->body['detail'] ?? null;

        if (is_string($detail) && $detail !== '') {
            return 'HTTP '.$this->status.': '.$detail;
        }

        return $this->transport ? 'transport error (no response)' : 'HTTP '.$this->status;
    }
}
