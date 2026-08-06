<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\ValueObjects;

/**
 * Result of verifying an audit chain segment.
 */
readonly class ChainVerification
{
    private function __construct(
        public bool $valid,
        public int $verifiedCount,
        public ?int $brokenAtSequence,
        public ?string $reason,
    ) {}

    public static function valid(int $verifiedCount): self
    {
        return new self(true, $verifiedCount, null, null);
    }

    public static function broken(int $sequence, string $reason): self
    {
        return new self(false, 0, $sequence, $reason);
    }
}
