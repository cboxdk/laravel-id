<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Exceptions;

use RuntimeException;

/**
 * Thrown when an org-admin-configured IdP endpoint (e.g. an OIDC `token_endpoint`)
 * points at a non-public destination — the platform refuses to make server-side
 * requests to loopback, private, link-local or reserved addresses (SSRF defense,
 * e.g. cloud metadata at 169.254.169.254).
 */
class UnsafeFederationUrl extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self('Unsafe federation URL: '.$reason);
    }
}
