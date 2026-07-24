<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

/**
 * The outcome of an authorization decision. Deny-by-default: the only way to
 * `allow()` is an explicit grant.
 */
readonly class Decision
{
    private function __construct(
        public bool $allowed,
        public string $reason,
    ) {}

    public static function allow(string $reason = 'granted'): self
    {
        return new self(true, $reason);
    }

    public static function deny(string $reason = 'no matching grant'): self
    {
        return new self(false, $reason);
    }
}
