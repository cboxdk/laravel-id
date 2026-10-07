<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/** How many of one kind of thing a step removed or rewrote — `passkeys: 2`. */
readonly class ErasureCount
{
    public function __construct(
        public string $item,
        public int $count,
    ) {}
}
