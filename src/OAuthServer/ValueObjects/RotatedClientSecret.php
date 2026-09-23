<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use DateTimeImmutable;

/**
 * The result of a rotation: the new secret's plaintext — readable exactly once, only its
 * hash is stored — and when the secrets it replaced stop working.
 *
 * `previousExpireAt` is null when there was nothing to retire; it equals the rotation
 * instant when the grace period was zero.
 */
readonly class RotatedClientSecret
{
    public function __construct(
        public string $secret,
        public ClientSecretSummary $summary,
        public ?DateTimeImmutable $previousExpireAt,
    ) {}
}
