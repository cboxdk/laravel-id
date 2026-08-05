<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Platform\Models\OrganizationApiKey;
use Cbox\Id\Platform\ValueObjects\IssuedOrganizationApiKey;
use DateTimeInterface;
use Illuminate\Support\Collection;

/**
 * Repository for account API keys — the management-plane machine credential. Never
 * environment-scoped: an account key operates above every environment the account
 * owns.
 */
interface OrganizationApiKeys
{
    /**
     * Issue a new key. Returns the stored record plus the one-time plaintext, which
     * is never recoverable afterwards. The key carries a role that bounds what it
     * can do, and an optional expiry.
     */
    public function issue(string $organizationId, string $name, MembershipRole $role, ?DateTimeInterface $expiresAt = null): IssuedOrganizationApiKey;

    /**
     * Resolve a presented plaintext token to its active key, recording use. Returns
     * null for an unknown, revoked, or expired token — the caller learns nothing
     * more than "not valid".
     */
    public function resolve(string $plaintext): ?OrganizationApiKey;

    /** Revoke a key immediately (idempotent). */
    public function revoke(string $id): void;

    /**
     * Every key issued for an account (including revoked/expired, for the audit
     * list), newest first.
     *
     * @return Collection<int, OrganizationApiKey>
     */
    public function forOrganization(string $organizationId): Collection;
}
