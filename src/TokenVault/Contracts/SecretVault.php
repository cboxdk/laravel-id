<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault\Contracts;

use Cbox\Id\TokenVault\Exceptions\LeaseDenied;
use Cbox\Id\TokenVault\Exceptions\SecretNotFound;
use Cbox\Id\TokenVault\Models\VaultGrant;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Cbox\Id\TokenVault\ValueObjects\SecretLease;
use DateTimeInterface;

/**
 * The AI token vault: a deny-by-default broker for downstream third-party
 * credentials that autonomous / AI agents must present to services they call
 * (OpenAI, GitHub, Google, …).
 *
 * The vault holds the credential SEALED at rest (Crypto SecretBox) and hands the
 * plaintext to an agent only through {@see lease()}, and only when an explicit,
 * revocable {@see grant()} authorizes that agent for that secret. Every store,
 * rotation, revocation, grant and lease is written to the hash-chained audit
 * trail — with the actor, purpose and provider, and NEVER the secret value.
 *
 * Everything is environment-owned: a secret stored in one environment is
 * structurally invisible to any other.
 */
interface SecretVault
{
    /**
     * Ingest a downstream credential, sealed at rest. `owner*` optionally scopes
     * the secret to an organization or user within the environment. Names are
     * unique per environment.
     */
    public function store(
        string $name,
        string $provider,
        string $secret,
        ?string $ownerType = null,
        ?string $ownerId = null,
        ?DateTimeInterface $expiresAt = null,
    ): VaultSecret;

    /**
     * Replace the sealed value (credential rotation), keeping the secret's id and
     * therefore its sealing context stable.
     *
     * @throws SecretNotFound
     */
    public function rotate(string $secretId, string $newSecret): VaultSecret;

    /**
     * Revoke a secret immediately and permanently: no future lease can open it.
     *
     * @throws SecretNotFound
     */
    public function revoke(string $secretId): void;

    /**
     * Authorize an agent client to lease a secret, optionally capping how long a
     * leased value may be held. Re-granting a previously revoked pair reactivates
     * it. Idempotent per (secret, client).
     *
     * @throws SecretNotFound
     */
    public function grant(string $secretId, string $clientId, ?int $maxTtlSeconds = null): VaultGrant;

    /**
     * Revoke an agent's authorization. A no-op if no live grant exists.
     */
    public function revokeGrant(string $secretId, string $clientId): void;

    /**
     * Broker the credential to an authorized agent for immediate use. Deny-by-default:
     * refused (uniformly) unless a live grant exists for the (secret, client) pair
     * and the secret is neither revoked nor expired. `purpose` is recorded on the
     * audit trail for accountability.
     *
     * @throws LeaseDenied
     */
    public function lease(string $secretId, string $clientId, string $purpose): SecretLease;
}
