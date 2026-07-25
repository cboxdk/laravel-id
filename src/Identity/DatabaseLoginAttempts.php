<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\LoginAttempts;
use Cbox\Id\Identity\Models\LoginAttemptCounter;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Organization\Contracts\Memberships;
use Illuminate\Support\Facades\DB;

/**
 * The default {@see LoginAttempts}: a per-subject counter in `login_attempt_counters`.
 *
 * Two durations are deliberately NOT policy fields, because a tenant setting them wrong
 * is worse than not setting them at all:
 *
 * - The counting WINDOW. Failures spread thinly over weeks are not an attack in
 *   progress, and counting them forever locks out people who simply mistype
 *   occasionally.
 * - The lockout DURATION. A lockout that lasts until an administrator intervenes turns
 *   the control into a denial-of-service tool: anyone who knows an email address can
 *   lock its owner out at will. NIST SP 800-63B prefers throttling over hard lockout for
 *   exactly this reason, so the lock expires on its own and the threshold exists to make
 *   guessing impractical rather than to punish.
 */
class DatabaseLoginAttempts implements LoginAttempts
{
    /** How long failures accumulate before the count starts again. */
    private const WINDOW_MINUTES = 15;

    /** How long a locked account stays locked. */
    private const LOCKOUT_MINUTES = 15;

    public function __construct(
        private readonly AuthPolicies $policies,
        private readonly Memberships $memberships,
        private readonly AuditLog $audit,
    ) {}

    public function isLockedOut(string $subjectId, ?string $organizationId = null): bool
    {
        if ($this->thresholdFor($subjectId, $organizationId) === null) {
            return false;
        }

        return LoginAttemptCounter::query()->where('user_id', $subjectId)->first()?->isLocked() ?? false;
    }

    public function recordFailure(string $subjectId, ?string $organizationId = null): bool
    {
        $threshold = $this->thresholdFor($subjectId, $organizationId);

        if ($threshold === null) {
            return false;
        }

        return DB::transaction(function () use ($subjectId, $threshold): bool {
            $counter = LoginAttemptCounter::query()
                ->where('user_id', $subjectId)
                ->lockForUpdate()
                ->first();

            $now = now();

            // Concurrent attempts on the same account are the NORMAL case under attack,
            // so the read-modify-write is serialized rather than left to race — two
            // parallel guesses must not both read "failures: 4" and both write 5.
            if ($counter === null) {
                LoginAttemptCounter::query()->create([
                    'user_id' => $subjectId,
                    'failures' => 1,
                    'window_started_at' => $now,
                ]);

                return $threshold <= 1;
            }

            $windowExpired = $counter->window_started_at === null
                || $counter->window_started_at->addMinutes(self::WINDOW_MINUTES)->isPast();

            $failures = $windowExpired ? 1 : $counter->failures + 1;

            $counter->forceFill([
                'failures' => $failures,
                'window_started_at' => $windowExpired ? $now : $counter->window_started_at,
                'locked_until' => $failures >= $threshold ? $now->copy()->addMinutes(self::LOCKOUT_MINUTES) : null,
            ])->save();

            if ($failures < $threshold) {
                return false;
            }

            $this->audit->record(new AuditEvent(
                action: 'user.locked_out',
                actorType: ActorType::System,
                targetType: 'user',
                targetId: $subjectId,
                context: ['failures' => $failures, 'threshold' => $threshold, 'minutes' => self::LOCKOUT_MINUTES],
            ));

            return true;
        });
    }

    public function clear(string $subjectId): void
    {
        LoginAttemptCounter::query()->where('user_id', $subjectId)->delete();
    }

    /**
     * The lowest threshold binding this subject, or null when no policy sets one.
     *
     * Same resolution as the rest of the policy engine: the environment baseline
     * tightened by every organization the subject belongs to, so an organization that
     * demands a tighter threshold gets it regardless of what context the caller had.
     */
    private function thresholdFor(string $subjectId, ?string $organizationId): ?int
    {
        if ($organizationId !== null) {
            return $this->policies->resolve($organizationId)->lockoutThreshold;
        }

        $policy = $this->policies->forEnvironment();

        foreach ($this->memberships->forUser($subjectId) as $membership) {
            $override = $this->policies->overrideFor($membership->organization_id);

            if ($override !== null) {
                $policy = $policy->tightenedWith($override);
            }
        }

        return $policy->lockoutThreshold;
    }
}
