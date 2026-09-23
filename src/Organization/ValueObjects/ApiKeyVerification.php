<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

use Carbon\CarbonInterface;
use Cbox\Id\Organization\Enums\MembershipRole;

/**
 * The answer to "is this customer API key good for my app, and what may it do?".
 *
 * Inactive carries nothing at all — not why, not whose. Every failure (unknown,
 * malformed, revoked, expired, another app's key, a holder who left) is the same value,
 * so the verification endpoint cannot be used as an oracle.
 *
 * `permissions` is already re-capped: the key's own list intersected with what the
 * holder holds for the app right now.
 *
 * `new ApiKeyVerification` is a valid, inactive answer, so a test can stub the contract
 * without building one by hand.
 */
readonly class ApiKeyVerification
{
    /**
     * @param  list<string>  $permissions
     */
    public function __construct(
        public bool $active = false,
        public ?string $keyId = null,
        public ?string $userId = null,
        public ?string $organizationId = null,
        public ?MembershipRole $organizationRole = null,
        public array $permissions = [],
        public ?string $clientId = null,
        public ?CarbonInterface $expiresAt = null,
    ) {}

    public static function inactive(): self
    {
        return new self;
    }

    /**
     * The endpoint's JSON body: `{active, key_id, sub, org, org_role, permissions[],
     * client_id, expires_at}` when active (`expires_at` ISO 8601 UTC, or null for a key
     * that does not expire), and exactly `{active: false}` otherwise.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        if (! $this->active) {
            return ['active' => false];
        }

        return [
            'active' => true,
            'key_id' => $this->keyId,
            'sub' => $this->userId,
            'org' => $this->organizationId,
            'org_role' => $this->organizationRole?->value,
            'permissions' => $this->permissions,
            'client_id' => $this->clientId,
            'expires_at' => $this->expiresAt?->toImmutable()->utc()->toIso8601ZuluString(),
        ];
    }
}
