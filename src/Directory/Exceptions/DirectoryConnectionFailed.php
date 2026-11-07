<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use RuntimeException;

/**
 * A pull connector could not reach or authenticate to the provider's API. Carries
 * a human-readable reason; the sync records it on the directory so an admin can see
 * why the last pull failed without exposing credentials.
 */
class DirectoryConnectionFailed extends RuntimeException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public static function make(string $provider, string $reason): self
    {
        return new self("Directory sync with {$provider} failed: {$reason}");
    }
}
