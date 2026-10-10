<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use DateTimeImmutable;

/**
 * What may be shown about a person's SMS factor: the number MASKED (`+45 ******78`), its
 * country, and whether it has been confirmed. The full number is never part of it — it
 * is opened from its seal only to send a text.
 */
readonly class SmsFactorDetails
{
    public function __construct(
        public string $maskedNumber,
        public string $country,
        public bool $confirmed,
        public ?DateTimeImmutable $confirmedAt = null,
    ) {}
}
