<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\BreachedPasswordCheck;
use Cbox\Id\Identity\Contracts\PasswordPolicyGuard;
use Cbox\Id\Identity\Exceptions\PolicyViolation;
use Cbox\Id\Identity\Models\PasswordHistoryEntry;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Illuminate\Contracts\Hashing\Hasher;

/**
 * Applies the tenant's {@see AuthPolicy} to a proposed
 * password.
 *
 * One enforcement point for every way a credential can be set — self-service change,
 * signup, and administrative assignment — so a rule cannot be honoured on one path and
 * quietly skipped on another.
 */
class PasswordPolicyEnforcer implements PasswordPolicyGuard
{
    public function __construct(
        private readonly AuthPolicies $policies,
        private readonly BreachedPasswordCheck $breaches,
        private readonly Hasher $hasher,
    ) {}

    public function assertAcceptable(string $password, ?string $userId = null, ?string $organizationId = null): void
    {
        $policy = $this->policies->resolve($organizationId);

        if (mb_strlen($password) < $policy->minLength) {
            throw PolicyViolation::tooShort($policy->minLength);
        }

        if ($policy->requireBreachCheck && $this->breaches->isBreached($password)) {
            throw PolicyViolation::breached();
        }

        if ($userId !== null && $policy->reuseHistory > 0 && $this->wasRecentlyUsed($userId, $password, $policy->reuseHistory)) {
            throw PolicyViolation::reused($policy->reuseHistory);
        }
    }

    public function remember(string $userId, string $passwordHash, ?string $organizationId = null): void
    {
        $keep = $this->policies->resolve($organizationId)->reuseHistory;

        if ($keep < 1) {
            return;
        }

        PasswordHistoryEntry::query()->create([
            'user_id' => $userId,
            'password_hash' => $passwordHash,
        ]);

        // Keep only as many as the policy actually compares against, so the store never
        // grows without bound and a loosened policy stops retaining what it won't use.
        $stale = PasswordHistoryEntry::query()
            ->where('user_id', $userId)
            ->orderByDesc('created_at')
            ->orderByDesc('id')
            ->skip($keep)
            ->take(1000)
            ->pluck('id');

        if ($stale->isNotEmpty()) {
            PasswordHistoryEntry::query()->whereIn('id', $stale)->delete();
        }
    }

    /**
     * Compare against the retained hashes. Each is a separate verify (hashes are salted,
     * so equality is not a string comparison) — bounded by the policy's history depth.
     */
    private function wasRecentlyUsed(string $userId, string $password, int $depth): bool
    {
        $recent = PasswordHistoryEntry::query()
            ->where('user_id', $userId)
            ->orderByDesc('created_at')
            ->orderByDesc('id')
            ->take($depth)
            ->pluck('password_hash');

        foreach ($recent as $hash) {
            if (is_string($hash) && $this->hasher->check($password, $hash)) {
                return true;
            }
        }

        return false;
    }
}
