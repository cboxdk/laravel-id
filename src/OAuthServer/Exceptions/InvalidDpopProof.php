<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

final class InvalidDpopProof extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self("Invalid DPoP proof: {$reason}");
    }
}
