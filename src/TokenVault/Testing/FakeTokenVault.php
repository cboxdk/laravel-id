<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault\Testing;

use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Exceptions\LeaseDenied;
use Cbox\Id\TokenVault\Exceptions\SecretNotFound;
use Cbox\Id\TokenVault\Models\VaultGrant;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Cbox\Id\TokenVault\ValueObjects\SecretLease;
use DateTimeInterface;
use Illuminate\Support\Str;
use PHPUnit\Framework\Assert;

/**
 * In-memory {@see SecretVault} for tests, in the spirit of Laravel's `Mail::fake()`.
 * It mirrors the real deny-by-default lease semantics (grant required, revoked /
 * expired refused, uniform {@see LeaseDenied}) so a test that fakes the vault still
 * exercises honest authorization behaviour — the plaintext lives only in memory and
 * never touches a database.
 */
class FakeTokenVault implements SecretVault
{
    private const DEFAULT_LEASE_TTL = 300;

    /** @var array<string, array{model: VaultSecret, secret: string}> */
    private array $secrets = [];

    /** @var array<string, VaultGrant> */
    private array $grants = [];

    /** @var list<array{secret_id: string, client_id: string, purpose: string}> */
    public array $leases = [];

    public function store(
        string $name,
        string $provider,
        string $secret,
        ?string $ownerType = null,
        ?string $ownerId = null,
        ?DateTimeInterface $expiresAt = null,
    ): VaultSecret {
        $model = new VaultSecret;
        $model->id = (string) Str::ulid();
        $model->fill([
            'name' => $name,
            'provider' => $provider,
            'key_version' => 1,
            'owner_type' => $ownerType,
            'owner_id' => $ownerId,
            'expires_at' => $expiresAt,
        ]);

        $this->secrets[$model->id] = ['model' => $model, 'secret' => $secret];

        return $model;
    }

    public function rotate(string $secretId, string $newSecret): VaultSecret
    {
        $entry = $this->secrets[$secretId] ?? throw SecretNotFound::forId($secretId);
        $entry['model']->rotated_at = now();
        $this->secrets[$secretId] = ['model' => $entry['model'], 'secret' => $newSecret];

        return $entry['model'];
    }

    public function revoke(string $secretId): void
    {
        $entry = $this->secrets[$secretId] ?? throw SecretNotFound::forId($secretId);
        $entry['model']->revoked_at = now();
    }

    public function grant(string $secretId, string $clientId, ?int $maxTtlSeconds = null): VaultGrant
    {
        if (! isset($this->secrets[$secretId])) {
            throw SecretNotFound::forId($secretId);
        }

        $grant = new VaultGrant;
        $grant->id = (string) Str::ulid();
        $grant->fill([
            'secret_id' => $secretId,
            'client_id' => $clientId,
            'max_ttl_seconds' => $maxTtlSeconds,
        ]);

        $this->grants[$secretId.'|'.$clientId] = $grant;

        return $grant;
    }

    public function revokeGrant(string $secretId, string $clientId): void
    {
        unset($this->grants[$secretId.'|'.$clientId]);
    }

    public function lease(string $secretId, string $clientId, string $purpose): SecretLease
    {
        $entry = $this->secrets[$secretId] ?? null;
        $grant = $this->grants[$secretId.'|'.$clientId] ?? null;

        if ($entry === null || $entry['model']->isRevoked() || $entry['model']->isExpired() || $grant === null) {
            throw LeaseDenied::make();
        }

        $ttl = $grant->max_ttl_seconds === null
            ? self::DEFAULT_LEASE_TTL
            : min(self::DEFAULT_LEASE_TTL, max(1, $grant->max_ttl_seconds));

        $this->leases[] = ['secret_id' => $secretId, 'client_id' => $clientId, 'purpose' => $purpose];

        return new SecretLease(
            secretId: $secretId,
            provider: $entry['model']->provider,
            secret: $entry['secret'],
            expiresAt: now()->addSeconds($ttl)->toDateTimeImmutable(),
        );
    }

    public function assertLeased(string $secretId): void
    {
        $match = array_filter($this->leases, fn (array $l): bool => $l['secret_id'] === $secretId);

        Assert::assertNotEmpty($match, "Expected secret [{$secretId}] to have been leased, but it was not.");
    }

    public function assertNothingLeased(): void
    {
        Assert::assertSame([], $this->leases, 'Expected no vault leases.');
    }

    public function assertLeaseCount(int $count): void
    {
        Assert::assertCount($count, $this->leases);
    }
}
