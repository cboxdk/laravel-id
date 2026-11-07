<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use RuntimeException;

/**
 * Pulling a manifest from an app's URL failed — a network error, a non-2xx
 * response, or a body that wasn't JSON. The app's declared catalog is left as-is.
 */
class ManifestFetchFailed extends RuntimeException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public static function make(string $reason): self
    {
        return new self("Failed to fetch app manifest: {$reason}");
    }
}
