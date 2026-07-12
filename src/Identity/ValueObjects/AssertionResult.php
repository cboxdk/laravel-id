<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/**
 * The trusted result of verifying a WebAuthn authentication assertion — the
 * authenticator's new signature counter.
 */
final readonly class AssertionResult
{
    public function __construct(
        public int $newSignCount,
    ) {}
}
