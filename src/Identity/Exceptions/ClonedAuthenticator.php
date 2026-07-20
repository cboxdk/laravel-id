<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

/**
 * The presented signature counter did not increase — the authenticator may have
 * been cloned. The assertion is refused.
 */
class ClonedAuthenticator extends RuntimeException
{
    public static function make(string $credentialId): self
    {
        return new self("Signature counter did not advance for credential [{$credentialId}]; possible cloned authenticator.");
    }
}
