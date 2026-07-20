<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

class UnknownCredential extends RuntimeException
{
    public static function make(string $credentialId): self
    {
        return new self("No registered passkey for credential [{$credentialId}].");
    }
}
