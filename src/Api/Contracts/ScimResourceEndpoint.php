<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Contracts;

use Cbox\Id\Api\Scim\ScimOutcome;
use Cbox\Id\Api\Support\ScimAttributeSelection;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\ValueObjects\DirectorySearch;

/**
 * The operations of one SCIM resource endpoint (RFC 7644 §3.2–§3.6), independent of
 * HTTP: each takes a decoded body and the precondition headers it needs, and answers a
 * {@see ScimOutcome}.
 *
 * It exists so a single-resource request and a `/Bulk` operation (§3.7) run the SAME
 * code — validation, provisioning, error mapping, ETag preconditions — and can never
 * drift: the controllers and the bulk processor are both thin callers of this.
 *
 * Every method is scoped to `$directory`: an id from another directory is a 404.
 */
interface ScimResourceEndpoint
{
    /**
     * The absolute URI of the resource `$id` (`meta.location`).
     */
    public function location(string $id): string;

    public function list(Directory $directory, DirectorySearch $search, ScimAttributeSelection $selection): ScimOutcome;

    /**
     * @param  string|null  $ifNoneMatch  the `If-None-Match` header; a match is a 304
     */
    public function show(Directory $directory, string $id, ScimAttributeSelection $selection, ?string $ifNoneMatch = null): ScimOutcome;

    /**
     * @param  array<array-key, mixed>  $body
     */
    public function create(Directory $directory, array $body): ScimOutcome;

    /**
     * @param  array<array-key, mixed>  $body
     * @param  string|null  $ifMatch  the `If-Match` header (or a bulk operation's
     *                                `version`); a mismatch is a 412
     */
    public function replace(Directory $directory, string $id, array $body, ?string $ifMatch = null): ScimOutcome;

    /**
     * @param  array<array-key, mixed>  $body  a PatchOp message
     */
    public function patch(Directory $directory, string $id, array $body, ?string $ifMatch = null): ScimOutcome;

    public function delete(Directory $directory, string $id, ?string $ifMatch = null): ScimOutcome;
}
