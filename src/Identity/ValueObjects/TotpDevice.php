<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use DateTimeImmutable;

readonly class TotpDevice
{
    public function __construct(
        public string $id,
        public string $name,
        public ?DateTimeImmutable $addedAt = null,
    ) {}
}
