<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault\Exceptions;

use RuntimeException;

/**
 * Uniform lease refusal. Every failure mode — unknown secret, no grant, a revoked
 * secret or grant, or an expired secret — raises this same exception with the same
 * generic message, so a caller cannot distinguish "you have no grant" from "that
 * secret does not exist" and use the vault as an enumeration oracle. The precise
 * reason is recorded on the audit trail (`vault.lease.denied`), not returned here.
 */
class LeaseDenied extends RuntimeException
{
    public static function make(): self
    {
        return new self('Lease denied.');
    }
}
