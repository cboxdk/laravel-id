<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Exceptions;

use RuntimeException;

/**
 * A hook endpoint URL failed the SSRF guard at registration — it points at a
 * non-public, internal, or otherwise disallowed address and is refused.
 */
class UnsafeActionUrl extends RuntimeException
{
    public static function forUrl(string $url): self
    {
        return new self("Refusing to register a hook endpoint at an unsafe URL: {$url}");
    }
}
