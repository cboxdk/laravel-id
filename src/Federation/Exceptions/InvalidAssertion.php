<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use RuntimeException;

/**
 * Thrown when an IdP response fails validation — bad signature, wrong issuer or
 * audience, expired, or malformed. Never carries the raw assertion.
 */
class InvalidAssertion extends RuntimeException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public static function make(string $reason): self
    {
        return new self('invalid assertion: '.$reason);
    }
}
