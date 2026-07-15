<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Exceptions;

use RuntimeException;

/**
 * Thrown when a downstream SCIM endpoint (base URL or OAuth token URL) points at
 * a non-public destination — the platform refuses to make requests to loopback,
 * private, link-local or reserved addresses (SSRF defense, e.g. cloud metadata at
 * 169.254.169.254).
 */
final class UnsafeScimUrl extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self('Unsafe SCIM endpoint URL: '.$reason);
    }
}
