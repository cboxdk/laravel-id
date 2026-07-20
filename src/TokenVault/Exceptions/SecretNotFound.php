<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault\Exceptions;

use RuntimeException;

/**
 * A management operation (rotate / revoke / grant) named a secret that does not
 * exist in the current environment. Surfaced only to the trusted caller managing
 * the vault — never on the lease path, which fails uniformly (see {@see LeaseDenied})
 * so a partially-trusted agent cannot probe which secret ids exist.
 */
class SecretNotFound extends RuntimeException
{
    public static function forId(string $secretId): self
    {
        return new self("No vault secret [{$secretId}] in this environment.");
    }
}
