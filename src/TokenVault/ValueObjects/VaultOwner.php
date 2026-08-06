<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault\ValueObjects;

use Cbox\Id\TokenVault\Enums\VaultOwnerType;

/**
 * The owner of a vault secret — and, on every read/mutate path, the scope the caller
 * is entitled to act within.
 *
 * Secrets are environment-scoped by the tenancy kernel, but an environment holds many
 * organizations, so the environment alone does not separate two tenants' credentials.
 * This is the boundary that does. It is a typed pair rather than two loose strings
 * precisely because the pair must always travel together: an owner id without its type
 * would let an organization id match a user-owned row.
 */
readonly class VaultOwner
{
    public function __construct(
        public VaultOwnerType $type,
        public string $id,
    ) {}

    public static function organization(string $id): self
    {
        return new self(VaultOwnerType::Organization, $id);
    }

    public static function user(string $id): self
    {
        return new self(VaultOwnerType::User, $id);
    }

    /** Rebuild from the persisted column pair; null when the row is unowned (platform). */
    public static function fromRow(?string $type, ?string $id): ?self
    {
        $owner = $type !== null ? VaultOwnerType::tryFrom($type) : null;

        return $owner !== null && $id !== null ? new self($owner, $id) : null;
    }

    public function is(?self $other): bool
    {
        return $other !== null && $this->type === $other->type && hash_equals($this->id, $other->id);
    }
}
