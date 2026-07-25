<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\BreachedPasswordCheck;
use Cbox\Id\Identity\Contracts\PasswordPolicyGuard;
use Cbox\Id\Identity\Exceptions\PolicyViolation;
use Cbox\Id\Identity\Models\PasswordHistoryEntry;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Organization\Contracts\Memberships;
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
        private readonly Memberships $memberships,
    ) {}

    public function assertAcceptable(string $password, ?string $userId = null, ?string $organizationId = null): void
    {
        $policy = $this->effectiveFor($userId, $organizationId);

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

    /**
     * The policy a proposed password must satisfy.
     *
     * A caller that names an organization gets that organization's effective policy. A
     * caller that does not — the credential primitive itself, which is handed a subject
     * and nothing else — gets the environment baseline tightened by EVERY organization
     * the subject belongs to. Resolving to the bare baseline instead would let a member
     * of a strict organization set a password that organization forbids, simply by
     * arriving through a path that happened not to carry org context; the same
     * tighten-only rule that stops an override weakening the baseline has to hold when
     * the org is inferred rather than passed.
     */
    private function effectiveFor(?string $userId, ?string $organizationId): AuthPolicy
    {
        if ($organizationId !== null || $userId === null) {
            return $this->policies->resolve($organizationId);
        }

        $policy = $this->policies->forEnvironment();

        foreach ($this->memberships->forUser($userId) as $membership) {
            $override = $this->policies->overrideFor($membership->organization_id);

            if ($override !== null) {
                $policy = $policy->tightenedWith($override);
            }
        }

        return $policy;
    }

    public function remember(string $userId, string $passwordHash, ?string $organizationId = null): void
    {
        $keep = $this->effectiveFor($userId, $organizationId)->reuseHistory;

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
