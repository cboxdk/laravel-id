<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use DateTimeImmutable;

/**
 * A code was texted — for enrolment or for a sign-in challenge. Carries what a page shows
 * ("we sent a code to +45 ******78, valid until …") and never the code.
 */
readonly class SmsCodeSent
{
    public function __construct(
        public string $challengeId,
        public string $maskedNumber,
        public DateTimeImmutable $expiresAt,
    ) {}
}
