<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\Organization\Enums\TokenScope;
use Cbox\Id\Organization\Exceptions\TokenScopeExceedsIssuerRole;
use Cbox\Id\Organization\Models\UserApiToken;
use Cbox\Id\Organization\ValueObjects\IssuedUserApiToken;
use Cbox\Id\Organization\ValueObjects\ResourceFamilies;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Collection;

/**
 * User-bound API tokens: a bearer credential that authenticates as the user
 * within one organization. Issuance is capped at the issuer's effective role
 * ({@see TokenScope::issuableBy()}) — a token never out-ranks its minter.
 */
interface UserApiTokens
{
    /**
     * Issue a token for the user. Every token carries a hard expiry: when
     * `expiresAt` is null a default TTL applies, so no token is open-ended.
     *
     * `resourceFamilies` is a {@see ResourceFamilies}, not an array, precisely so
     * that "no restriction expressed" and "restricted to nothing" cannot be the
     * same value: omitting the argument (or passing null) is
     * {@see ResourceFamilies::unrestricted()}, while
     * {@see ResourceFamilies::none()} issues a token permitted on no family at
     * all. An array used to collapse those two into an every-family token.
     *
     * @throws TokenScopeExceedsIssuerRole
     */
    public function issue(
        string $organizationId,
        string $userId,
        string $name,
        TokenScope $scope,
        ?ResourceFamilies $resourceFamilies = null,
        ?DateTimeInterface $expiresAt = null,
    ): IssuedUserApiToken;

    /**
     * Resolve a presented plaintext to its live token, stamping last_used_at.
     * Null for unknown, revoked, or expired tokens — never an exception, so
     * an attacker learns nothing about why a credential failed.
     */
    public function resolve(string $plaintext): ?UserApiToken;

    public function revoke(string $organizationId, string $tokenId): void;

    /**
     * The user's tokens in an organization, newest first.
     *
     * @return Collection<int, UserApiToken>
     */
    public function forUser(string $organizationId, string $userId): Collection;
}
