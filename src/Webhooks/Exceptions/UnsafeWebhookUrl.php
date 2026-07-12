<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Exceptions;

use RuntimeException;

/**
 * Thrown when a webhook URL points at a non-public destination — the platform
 * refuses to make requests to loopback, private, link-local or reserved
 * addresses (SSRF defense, e.g. cloud metadata at 169.254.169.254).
 */
final class UnsafeWebhookUrl extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self('Unsafe webhook URL: '.$reason);
    }
}
