<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Scim;

use Cbox\Id\Api\Exceptions\InvalidScimRequest;
use Cbox\Id\Scim\Enums\ScimPatchOp;

/**
 * Reads the `Operations` of a PATCH request body (RFC 7644 §3.5.2).
 *
 * §3.5.2 makes the member mandatory and defines it as "an array of one or more PATCH
 * operations". Both endpoints used to degrade anything else to `[]` and then answer 200
 * with the full, unchanged resource — so a connector that sent lower-case
 * `operations`, or a proxy that normalized the key, had its `active:false` push recorded
 * as applied and never retried it.
 *
 * The lookup is CASE-INSENSITIVE, because RFC 7643 §2.1 says so without exception:
 * "Attribute names are case insensitive". A body spelling `operations` is legal SCIM.
 * This folds the top-level KEY only — the `op` VALUES are folded where they are parsed
 * ({@see ScimPatchOp::tryParse()}).
 */
class ScimPatchRequest
{
    /**
     * @param  array<array-key, mixed>  $body
     * @return list<array<array-key, mixed>>
     *
     * @throws InvalidScimRequest
     */
    public static function operations(array $body): array
    {
        $operations = array_change_key_case($body, CASE_LOWER)['operations'] ?? null;

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
}
