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
 * ON BY DEFAULT. When no environment or organization policy names a threshold, the
 * deployment default `cbox-id.lockout.threshold` (10) applies. It used to be "off until a
 * policy sets it", which meant a fresh install accepted an unbounded online guessing run
 * against any one account — the safe state was the one an operator had to remember to
 * opt into. A policy that names a threshold still wins, and `0` turns the default off.
 *
 * Two durations are deliberately NOT policy fields, because a tenant setting them wrong
 * is worse than not setting them at all — they are deployment configuration
 * (`cbox-id.lockout.window_minutes` / `duration_minutes`, both 15 by default):
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
    /** How long failures accumulate before the count starts again, absent config. */
    private const DEFAULT_WINDOW_MINUTES = 15;

    /** How long a locked account stays locked, absent config. */
    private const DEFAULT_LOCKOUT_MINUTES = 15;

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
        // EVERY failure is recorded, not only the one that trips the lock.
        //
        // Until now the sole audit entry here was `user.locked_out`, written when the
        // counter crossed the threshold. Everything below it — and everything on a
        // deployment with no lockout policy at all, which returns two lines down — left
        // no trace whatsoever.
        //
        // That is precisely the wrong shape for the attack this counter exists to bound.
        // Password spraying is deliberately quiet: three guesses each against five
        // thousand accounts, under a threshold of five, locks nobody out and produced an
        // audit trail containing literally nothing. The one signal that would have shown
        // it — many accounts, few attempts each, one source — was the one never written.
        //
        // The IP comes from the current request. Laravel's helper always returns a
        // Request — outside HTTP it is a synthetic one whose `ip()` is null, which is
        // the honest answer for a queue worker or a console command rather than a
        // fabricated address. `DatabaseOtpService` audits both branches this way already.
        $this->audit->record(new AuditEvent(
            action: 'user.sign_in_failed',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $subjectId,
            organizationId: $organizationId,
            ip: request()->ip(),
        ));

        $threshold = $this->thresholdFor($subjectId, $organizationId);

        if ($threshold === null) {
            return false;
        }

        $windowMinutes = self::minutes('window_minutes', self::DEFAULT_WINDOW_MINUTES);
        $lockoutMinutes = self::minutes('duration_minutes', self::DEFAULT_LOCKOUT_MINUTES);

        return DB::transaction(function () use ($subjectId, $threshold, $windowMinutes, $lockoutMinutes): bool {
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
                || $counter->window_started_at->addMinutes($windowMinutes)->isPast();

            $failures = $windowExpired ? 1 : $counter->failures + 1;

            $counter->forceFill([
                'failures' => $failures,
                'window_started_at' => $windowExpired ? $now : $counter->window_started_at,
                'locked_until' => $failures >= $threshold ? $now->copy()->addMinutes($lockoutMinutes) : null,
            ])->save();

            if ($failures < $threshold) {
                return false;
            }

            $this->audit->record(new AuditEvent(
                action: 'user.locked_out',
                actorType: ActorType::System,
                targetType: 'user',
                targetId: $subjectId,
                context: ['failures' => $failures, 'threshold' => $threshold, 'minutes' => $lockoutMinutes],
            ));

            return true;
        });
    }

    public function clear(string $subjectId): void
    {
        LoginAttemptCounter::query()->where('user_id', $subjectId)->delete();
    }

    /**
     * The lowest threshold binding this subject, falling back to the deployment default
     * when no policy sets one. Null only when the default is switched off too.
     *
     * Same resolution as the rest of the policy engine: the environment baseline
     * tightened by every organization the subject belongs to, so an organization that
     * demands a tighter threshold gets it regardless of what context the caller had.
     */
    private function thresholdFor(string $subjectId, ?string $organizationId): ?int
    {
        return $this->policyThresholdFor($subjectId, $organizationId) ?? self::defaultThreshold();
    }

    private function policyThresholdFor(string $subjectId, ?string $organizationId): ?int
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

    /**
     * `cbox-id.lockout.threshold`, read leniently because it arrives from an env var: a
     * numeric string is a number, and anything that is not a positive integer — `0`,
     * empty, `null`, garbage — means "no deployment default". Refusing to boot over a
     * typo here would be worse than the old default it replaces.
     */
    private static function defaultThreshold(): ?int
    {
        $configured = config('cbox-id.lockout.threshold');

        if (is_int($configured)) {
            return $configured > 0 ? $configured : null;
        }

        if (is_string($configured) && ctype_digit($configured)) {
            $value = (int) $configured;

            return $value > 0 ? $value : null;
        }

        return null;
    }

    /**
     * A window/duration in minutes from config. A non-positive or unparseable value
     * falls back to the built-in default rather than to zero: a zero-minute lock is no
     * lock, and a zero-minute window never accumulates a second failure, so either would
     * silently switch the control off.
     */
    private static function minutes(string $key, int $default): int
    {
        $configured = config('cbox-id.lockout.'.$key);

        $value = match (true) {
            is_int($configured) => $configured,
            is_string($configured) && ctype_digit($configured) => (int) $configured,
            default => 0,
        };

        return $value > 0 ? $value : $default;
    }
}
