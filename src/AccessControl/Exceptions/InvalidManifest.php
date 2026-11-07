<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use InvalidArgumentException;

/**
 * A submitted app manifest was malformed — a bad shape, a missing key, or a role
 * referencing a permission it never declared. Rejected whole; a partial catalog is
 * never persisted.
 */
class InvalidManifest extends InvalidArgumentException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public static function make(string $reason): self
    {
        return new self("Invalid app manifest: {$reason}");
    }
}
