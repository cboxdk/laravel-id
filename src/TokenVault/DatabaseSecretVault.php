<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Exceptions\LeaseDenied;
use Cbox\Id\TokenVault\Exceptions\SecretNotFound;
use Cbox\Id\TokenVault\Models\VaultGrant;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Cbox\Id\TokenVault\ValueObjects\SecretLease;
use DateTimeInterface;
use Illuminate\Support\Str;

/**
 * Database-backed {@see SecretVault}. This class carries the vault's security
 * guarantees:
 *
 *  - SEALED AT REST — a credential is stored only as a SecretBox ciphertext bound
 *    (AEAD) to its own row id; the plaintext is opened solely inside {@see lease()}
 *    and never persisted unsealed, logged, or written to an audit row.
 *  - DENY-BY-DEFAULT — every mutation and every lease first calls
 *    {@see EnvironmentContext::requireEnvironment()} (hard tenancy), and a lease is
 *    refused unless a live grant exists for the exact (secret, client) pair; the
 *    refusal is UNIFORM (no enumeration oracle) and its reason is audited, not
 *    returned.
 *  - REVOCABLE — a revoked secret or grant, or an expired secret, can never be
 *    leased again; revocation takes effect on the next lease.
 *  - ACCOUNTABLE — store / rotate / revoke / grant / lease are all recorded on the
 *    hash-chained audit trail, with the acting client and the stated purpose.
 */
final class DatabaseSecretVault implements SecretVault
{
    public function __construct(
        private readonly SecretBox $secretBox,
        private readonly AuditLog $audit,
        private readonly EnvironmentContext $environments,
        private readonly int $defaultLeaseTtlSeconds,
    ) {}

    public function store(
        string $name,
        string $provider,
        string $secret,
        ?string $ownerType = null,
        ?string $ownerId = null,
        ?DateTimeInterface $expiresAt = null,
    ): VaultSecret {
        $this->environments->requireEnvironment();

        $model = new VaultSecret;
        // The id is assigned before sealing so secretContext() (which binds the
        // ciphertext to this row) is stable and available at seal time.
        $model->id = (string) Str::ulid();
        $model->fill([
            'name' => $name,
            'provider' => $provider,
            'key_version' => 1,
            'owner_type' => $ownerType,
            'owner_id' => $ownerId,
            'expires_at' => $expiresAt,
        ]);
        $model->secret_encrypted = $this->secretBox->seal($secret, $model->secretContext());
        $model->save();

        $this->audit->record(new AuditEvent(
            action: 'vault.secret.stored',
            actorType: ActorType::System,
            targetType: 'vault_secret',
            targetId: $model->id,
            context: ['provider' => $provider, 'name' => $name],
        ));

        return $model;
    }

    public function rotate(string $secretId, string $newSecret): VaultSecret
    {
        $this->environments->requireEnvironment();

        $secret = VaultSecret::query()->whereKey($secretId)->first();

        if ($secret === null) {
            throw SecretNotFound::forId($secretId);
        }

        // Re-seal under the same context (the id is unchanged) so the rotated blob
        // stays bound to this row.
        $secret->secret_encrypted = $this->secretBox->seal($newSecret, $secret->secretContext());
        $secret->rotated_at = now();
        $secret->save();

        $this->audit->record(new AuditEvent(
            action: 'vault.secret.rotated',
            actorType: ActorType::System,
            targetType: 'vault_secret',
            targetId: $secret->id,
            context: ['provider' => $secret->provider],
        ));

        return $secret;
    }

    public function revoke(string $secretId): void
    {
        $this->environments->requireEnvironment();

        $secret = VaultSecret::query()->whereKey($secretId)->first();

        if ($secret === null) {
            throw SecretNotFound::forId($secretId);
        }

        if ($secret->isRevoked()) {
            return;
        }

        $secret->revoked_at = now();
        $secret->save();

        $this->audit->record(new AuditEvent(
            action: 'vault.secret.revoked',
            actorType: ActorType::System,
            targetType: 'vault_secret',
            targetId: $secret->id,
        ));
    }

    public function grant(string $secretId, string $clientId, ?int $maxTtlSeconds = null): VaultGrant
    {
        $this->environments->requireEnvironment();

        // Deny-by-default: you can only grant access to a secret that exists in
        // this environment.
        $secret = VaultSecret::query()->whereKey($secretId)->first();

        if ($secret === null) {
            throw SecretNotFound::forId($secretId);
        }

        $grant = VaultGrant::query()
            ->where('secret_id', $secretId)
            ->where('client_id', $clientId)
            ->first();

        if ($grant === null) {
            $grant = new VaultGrant;
            $grant->id = (string) Str::ulid();
            $grant->fill(['secret_id' => $secretId, 'client_id' => $clientId]);
        }

        // Re-granting reactivates a previously revoked pair.
        $grant->max_ttl_seconds = $maxTtlSeconds;
        $grant->revoked_at = null;
        $grant->save();

        $this->audit->record(new AuditEvent(
            action: 'vault.grant.created',
            actorType: ActorType::System,
            targetType: 'vault_secret',
            targetId: $secretId,
            context: ['client_id' => $clientId, 'max_ttl_seconds' => $maxTtlSeconds],
        ));

        return $grant;
    }

    public function revokeGrant(string $secretId, string $clientId): void
    {
        $this->environments->requireEnvironment();

        $grant = VaultGrant::query()
            ->where('secret_id', $secretId)
            ->where('client_id', $clientId)
            ->whereNull('revoked_at')
            ->first();

        if ($grant === null) {
            return;
        }

        $grant->revoked_at = now();
        $grant->save();

        $this->audit->record(new AuditEvent(
            action: 'vault.grant.revoked',
            actorType: ActorType::System,
            targetType: 'vault_secret',
            targetId: $secretId,
            context: ['client_id' => $clientId],
        ));
    }

    public function lease(string $secretId, string $clientId, string $purpose): SecretLease
    {
        $this->environments->requireEnvironment();

        $secret = VaultSecret::query()->whereKey($secretId)->first();
        $grant = $secret === null
            ? null
            : VaultGrant::query()
                ->where('secret_id', $secretId)
                ->where('client_id', $clientId)
                ->whereNull('revoked_at')
                ->first();

        // Every failure mode fails the SAME way (LeaseDenied) so a caller cannot
        // tell "no such secret" from "no grant"; the real reason is audited only.
        if ($secret === null || $secret->isRevoked() || $secret->isExpired() || $grant === null) {
            $reason = match (true) {
                $secret === null => 'unknown_secret',
                $secret->isRevoked() => 'secret_revoked',
                $secret->isExpired() => 'secret_expired',
                default => 'no_grant',
            };

            $this->audit->record(new AuditEvent(
                action: 'vault.lease.denied',
                actorType: ActorType::Service,
                actorId: $clientId,
                targetType: 'vault_secret',
                targetId: $secretId,
                context: ['reason' => $reason, 'purpose' => $purpose],
            ));

            throw LeaseDenied::make();
        }

        $plaintext = $this->secretBox->open($secret->secret_encrypted, $secret->secretContext());

        $ttl = $this->leaseTtlSeconds($grant->max_ttl_seconds);
        $expiresAt = now()->addSeconds($ttl);

        $this->audit->record(new AuditEvent(
            action: 'vault.secret.leased',
            actorType: ActorType::Service,
            actorId: $clientId,
            targetType: 'vault_secret',
            targetId: $secret->id,
            context: ['provider' => $secret->provider, 'purpose' => $purpose, 'ttl_seconds' => $ttl],
        ));

        return new SecretLease(
            secretId: $secret->id,
            provider: $secret->provider,
            secret: $plaintext,
            expiresAt: $expiresAt->toDateTimeImmutable(),
        );
    }

    /**
     * The effective lease window: the vault-wide default, which a per-grant cap can
     * only shorten (never extend past the ceiling).
     */
    private function leaseTtlSeconds(?int $grantMax): int
    {
        if ($grantMax === null) {
            return $this->defaultLeaseTtlSeconds;
        }

        return min($this->defaultLeaseTtlSeconds, max(1, $grantMax));
    }
}
