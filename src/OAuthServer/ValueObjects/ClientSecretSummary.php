<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Models\StoredClientSecret;
use DateTimeImmutable;

/**
 * One live secret of a client, as a console may show it: never the secret, never its
 * hash. `hint` is null for a secret that predates per-secret storage.
 */
readonly class ClientSecretSummary
{
    public function __construct(
        public string $id,
        public ?string $hint,
        public ?DateTimeImmutable $createdAt,
        public ?DateTimeImmutable $expiresAt,
        public ?DateTimeImmutable $lastUsedAt,
    ) {}

    public static function of(StoredClientSecret $secret): self
    {
        return new self(
            id: $secret->id,
            hint: $secret->hint,
            createdAt: $secret->created_at?->toDateTimeImmutable(),
            expiresAt: $secret->expires_at?->toDateTimeImmutable(),
            lastUsedAt: $secret->last_used_at?->toDateTimeImmutable(),
        );
    }

    /** Whether this secret is on its way out — superseded by a rotation, still inside its grace period. */
    public function isExpiring(): bool
    {
        return $this->expiresAt !== null;
    }
}
