<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Exceptions;

use RuntimeException;

/**
 * A PATCH operation targeted an attribute this server does not map.
 *
 * RFC 7644 §3.5.2 requires an unmatched target to be refused. Ignoring it and answering
 * 200 is worse than useless: the calling IdP records a successful write, never retries,
 * and the drift is permanent and invisible on both sides.
 */
class UnsupportedScimPath extends RuntimeException
{
    public static function forPath(string $path): self
    {
        return new self("The attribute path [{$path}] is not supported by this server.");
    }
}
