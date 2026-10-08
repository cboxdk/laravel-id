<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Scim;

use Cbox\Id\Scim\ScimSchema;

/**
 * The result of one SCIM operation, before it is an HTTP response — so the same
 * operation can answer a single-resource request AND stand as one entry of a `/Bulk`
 * response (RFC 7644 §3.7.3), which carries exactly these parts: a status, a body (for
 * an error, the §3.12 Error), the resource's `location`, and its `version`.
 */
readonly class ScimOutcome
{
    /**
     * @param  array<string, mixed>|null  $body
     */
    public function __construct(
        public int $status,
        public ?array $body = null,
        public ?string $location = null,
        public ?string $version = null,
    ) {}

    /**
     * A resource (or a ListResponse) answered with `$status`. Its `meta.location` and
     * `meta.version` become the outcome's location and version — the
     * `Content-Location`/`Location` and `ETag` headers of a single-resource response.
     *
     * @param  array<string, mixed>  $body
     */
    public static function resource(array $body, int $status = 200): self
    {
        $meta = $body['meta'] ?? null;
        $location = is_array($meta) ? ($meta['location'] ?? null) : null;
        $version = is_array($meta) ? ($meta['version'] ?? null) : null;

        return new self(
            $status,
            $body,
            is_string($location) && $location !== '' ? $location : null,
            is_string($version) && $version !== '' ? $version : null,
        );
    }

    /**
     * An RFC 7644 §3.12 Error.
     */
    public static function error(int $status, string $detail, ?string $scimType = null, ?string $location = null): self
    {
        return new self($status, ScimSchema::error((string) $status, $detail, $scimType), $location);
    }

    /**
     * RFC 7644 Table 8: "Failed to update. Resource has changed on the server."
     */
    public static function preconditionFailed(?string $location = null): self
    {
        return self::error(412, 'Failed to update. Resource has changed on the server.', null, $location);
    }

    public static function noContent(?string $location = null): self
    {
        return new self(204, null, $location);
    }

    /**
     * `304 Not Modified` for a conditional GET whose `If-None-Match` still matches
     * (RFC 7644 §3.14: "the service provider simply returns an empty body").
     */
    public static function notModified(string $version, ?string $location = null): self
    {
        return new self(304, null, $location, $version);
    }

    public function failed(): bool
    {
        return $this->status >= 400;
    }

    /**
     * The `id` of the resource in the body, when there is one.
     */
    public function id(): ?string
    {
        $id = $this->body['id'] ?? null;

        return is_string($id) && $id !== '' ? $id : null;
    }
}
