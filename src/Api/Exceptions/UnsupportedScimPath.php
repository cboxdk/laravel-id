<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Exceptions;

use RuntimeException;

/**
 * A PATCH operation this server cannot honour — an unmatched attribute path, or an
 * unknown/missing `op`.
 *
 * RFC 7644 §3.5.2 defines only `add`/`remove`/`replace` and requires an unmatched
 * target to be refused. Ignoring either and answering 200 is worse than useless: the
 * calling IdP records a successful write, never retries, and the drift is permanent and
 * invisible on both sides. The carried {@see $scimType} lets the controller emit the
 * correct RFC 7644 §3.12 keyword (`invalidPath` vs `invalidSyntax`).
 */
class UnsupportedScimPath extends RuntimeException
{
    /**
     * @param  string  $scimType  the SCIM error keyword (RFC 7644 §3.12)
     */
    public function __construct(string $message, public readonly string $scimType = 'invalidPath')
    {
        parent::__construct($message);
    }

    public static function forPath(string $path): self
    {
        return new self("The attribute path [{$path}] is not supported by this server.");
    }

    public static function forOp(string $op): self
    {
        return new self(
            $op === '' ? 'Missing PATCH op.' : "Unsupported PATCH op: {$op}.",
            'invalidSyntax',
        );
    }
}
