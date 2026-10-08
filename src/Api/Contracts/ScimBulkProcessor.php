<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Contracts;

use Cbox\Id\Api\Scim\DefaultScimBulkProcessor;
use Cbox\Id\Api\Scim\ScimOutcome;
use Cbox\Id\Directory\Models\Directory;

/**
 * Executes a SCIM `BulkRequest` (RFC 7644 §3.7) against one directory and answers its
 * `BulkResponse`. Bound to {@see DefaultScimBulkProcessor}.
 */
interface ScimBulkProcessor
{
    /**
     * The most operations one request may carry (`bulk.maxOperations`, §3.7.4).
     */
    public function maxOperations(): int;

    /**
     * The largest request body, in bytes (`bulk.maxPayloadSize`, §3.7.4).
     */
    public function maxPayloadSize(): int;

    /**
     * @param  array<array-key, mixed>  $request  the decoded BulkRequest
     */
    public function process(Directory $directory, array $request): ScimOutcome;
}
