<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use RuntimeException;

/**
 * A manifest URL was refused by the SSRF guard — it resolved to a private,
 * reserved, loopback, or cloud-metadata address, so the platform will not fetch it.
 */
class UnsafeManifestUrl extends RuntimeException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public static function make(string $reason): self
    {
        return new self("Refused to fetch manifest from an unsafe URL: {$reason}");
    }
}
