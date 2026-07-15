<?php

declare(strict_types=1);

namespace Cbox\Id\Otp;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Otp\Contracts\OtpChannels;
use Cbox\Id\Otp\Contracts\OtpHasher;
use Cbox\Id\Otp\Contracts\OtpService;
use Cbox\Id\Otp\Exceptions\OtpRateLimitExceeded;
use Cbox\Id\Otp\Models\OtpChallenge as OtpChallengeModel;
use Cbox\Id\Otp\ValueObjects\OtpChallenge;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;
use Cbox\Id\Otp\ValueObjects\OtpResult;
use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Support\Facades\DB;

/**
 * Database-backed {@see OtpService}. This class carries the security guarantees;
 * the anti-abuse and honest-crypto invariants live here:
 *
 *  - CODE GENERATION — {@see generateCode()} draws from {@see random_int} (CSPRNG),
 *    never mt_rand, and zero-pads to the configured length.
 *  - HASH AT REST — only {@see OtpHasher::hash()} of the code is stored; the raw
 *    code is passed to the channel and then dropped. It is never persisted, logged,
 *    returned, or placed in an audit row or exception.
 *  - CONSTANT-TIME MISS PATH — every verify path runs {@see OtpHasher::verify()}
 *    (a {@see hash_equals} compare), including when no challenge is found (against a
 *    decoy hash), so a wrong code and an unknown recipient are indistinguishable by
 *    timing and no enumeration oracle exists.
 *  - TTL / SINGLE-USE / ATTEMPT-CAP — enforced server-side under a row lock inside
 *    a transaction: expired, consumed, or attempt-capped challenges fail.
 *  - RATE LIMITS — layered, via Laravel's {@see RateLimiter}: ISSUE is capped both
 *    per recipient+purpose+ip AND per recipient across all purposes/IPs (the latter
 *    is what actually bounds SMS-bombing when an attacker rotates IPs/purposes);
 *    VERIFY is capped both globally per-ip AND (on the recipient path) per
 *    recipient+purpose across IPs (anti-brute-force). The at-rest per-challenge
 *    attempt cap is the last-resort bound independent of any cache-backed limiter.
 */
class DatabaseOtpService implements OtpService
{
    public function __construct(
        private readonly OtpChannels $channels,
        private readonly OtpHasher $hasher,
        private readonly AuditLog $audit,
        private readonly EnvironmentContext $environments,
        private readonly RateLimiter $limiter,
        private readonly int $codeLength,
        private readonly int $ttlSeconds,
        private readonly int $maxAttempts,
        private readonly int $issueMaxPerWindow,
        private readonly int $issuePerRecipientMax,
        private readonly int $issueWindowSeconds,
        private readonly int $verifyMaxPerWindow,
        private readonly int $verifyPerRecipientMax,
        private readonly int $verifyWindowSeconds,
    ) {}

    public function issue(string $purpose, string $recipient, string $channel, ?string $ip = null): OtpChallenge
    {
        // Deny-by-default on both dimensions BEFORE any state changes: refuse if no
        // environment is in context (env isolation), and refuse an unregistered
        // channel key rather than silently dropping the request.
        $this->environments->requireEnvironment();
        $sender = $this->channels->channel($channel);

        // Two independent issue caps, both checked BEFORE either is charged so a
        // rejection never spends the other's budget:
        //   - narrow (recipient+purpose+ip): the ordinary anti-replay throttle;
        //   - broad  (recipient across all purposes/IPs): bounds SMS-bombing when an
        //     attacker rotates IPs or purposes to slip past the narrow key.
        $throttleKey = $this->issueKey($purpose, $recipient, $ip);
        $recipientKey = $this->issueRecipientKey($recipient);

        $this->guardIssueThrottle($throttleKey, $this->issueMaxPerWindow);
        $this->guardIssueThrottle($recipientKey, $this->issuePerRecipientMax);

        $this->limiter->hit($throttleKey, $this->issueWindowSeconds);
        $this->limiter->hit($recipientKey, $this->issueWindowSeconds);

        $code = $this->generateCode();
        $expiresAt = now()->addSeconds($this->ttlSeconds);

        $challenge = OtpChallengeModel::query()->create([
            'purpose' => $purpose,
            'channel' => $channel,
            'recipient' => $recipient,
            'code_hash' => $this->hasher->hash($code),
            'expires_at' => $expiresAt,
            'attempts' => 0,
            'max_attempts' => $this->maxAttempts,
        ]);

        $sender->deliver(new OtpDelivery(
            challengeId: $challenge->id,
            recipient: $recipient,
            code: $code,
            purpose: $purpose,
            channel: $channel,
            expiresAt: $expiresAt->toDateTimeImmutable(),
            ttlSeconds: $this->ttlSeconds,
        ));

        // The audit row records that a code was issued and to whom — never the code.
        $this->audit->record(new AuditEvent(
            action: 'otp.issued',
            actorType: ActorType::System,
            targetType: 'otp_challenge',
            targetId: $challenge->id,
            context: ['purpose' => $purpose, 'channel' => $channel, 'recipient' => $recipient],
            ip: $ip,
        ));

        return new OtpChallenge(
            id: $challenge->id,
            purpose: $purpose,
            channel: $channel,
            recipient: $recipient,
            expiresAt: $expiresAt->toDateTimeImmutable(),
            maxAttempts: $this->maxAttempts,
        );
    }

    public function verify(string $challengeId, string $code, ?string $ip = null): OtpResult
    {
        $this->environments->requireEnvironment();

        if ($this->verifyThrottled($ip)) {
            return OtpResult::rateLimited();
        }

        return DB::transaction(fn (): OtpResult => $this->settle(
            fn () => OtpChallengeModel::query()->whereKey($challengeId)->lockForUpdate()->first(),
            $code,
        ));
    }

    public function verifyLatest(string $purpose, string $recipient, string $code, ?string $ip = null): OtpResult
    {
        $this->environments->requireEnvironment();

        // Per-IP throttle AND a per-recipient throttle: the finder below resolves the
        // recipient's latest LIVE challenge, so without a recipient-scoped cap an
        // attacker spraying from many IPs could brute-force it across its short window.
        if ($this->verifyThrottled($ip) || $this->verifyRecipientThrottled($purpose, $recipient)) {
            return OtpResult::rateLimited();
        }

        return DB::transaction(fn (): OtpResult => $this->settle(
            // Only the newest LIVE, UNLOCKED challenge is a candidate. Skipping expired
            // and attempt-capped rows closes two holes at once: (1) no expired/locked
            // status leaks back as a distinguishing signal on the recipient path, and
            // (2) a newer challenge that an attacker deliberately locked can no longer
            // shadow an older still-valid one the legitimate user is trying to redeem.
            fn () => OtpChallengeModel::query()
                ->where('purpose', $purpose)
                ->where('recipient', $recipient)
                ->whereNull('consumed_at')
                ->where('expires_at', '>', now())
                ->whereColumn('attempts', '<', 'max_attempts')
                ->orderByDesc('created_at')
                ->lockForUpdate()
                ->first(),
            $code,
        ));
    }

    /**
     * The verify state machine. The hash-compare runs on EVERY path (a decoy hash
     * when there is no challenge), so no branch returns before the constant-time
     * work is done — there is no timing or enumeration oracle.
     *
     * @param  Closure(): (OtpChallengeModel|null)  $finder
     */
    private function settle(Closure $finder, string $code): OtpResult
    {
        $challenge = $finder();

        if ($challenge === null) {
            // No challenge in THIS environment (deny-by-default scope) — still spend
            // the same compare so a miss is indistinguishable from a wrong code.
            $this->hasher->verify($code, $this->hasher->decoy());

            return OtpResult::invalid();
        }

        // A consumed code is spent: fail as "invalid" (no distinguishing signal),
        // but still perform the compare for uniform timing.
        if ($challenge->isConsumed()) {
            $this->hasher->verify($code, $challenge->code_hash);

            return OtpResult::invalid();
        }

        if ($challenge->isExpired()) {
            $this->hasher->verify($code, $challenge->code_hash);

            return OtpResult::expired($challenge->id);
        }

        if ($challenge->isLocked()) {
            $this->hasher->verify($code, $challenge->code_hash);

            return OtpResult::locked($challenge->id);
        }

        $matches = $this->hasher->verify($code, $challenge->code_hash);

        if (! $matches) {
            $challenge->forceFill(['attempts' => $challenge->attempts + 1])->save();

            $this->audit->record(new AuditEvent(
                action: 'otp.verify_failed',
                actorType: ActorType::System,
                targetType: 'otp_challenge',
                targetId: $challenge->id,
                context: ['purpose' => $challenge->purpose, 'attempts' => $challenge->attempts],
            ));

            if ($challenge->isLocked()) {
                $this->audit->record(new AuditEvent(
                    action: 'otp.locked',
                    actorType: ActorType::System,
                    targetType: 'otp_challenge',
                    targetId: $challenge->id,
                    context: ['purpose' => $challenge->purpose],
                ));
            }

            return OtpResult::invalid();
        }

        // Success: consume single-use and count the attempt in one write under the lock.
        $challenge->forceFill([
            'attempts' => $challenge->attempts + 1,
            'consumed_at' => now(),
        ])->save();

        $this->audit->record(new AuditEvent(
            action: 'otp.verified',
            actorType: ActorType::System,
            targetType: 'otp_challenge',
            targetId: $challenge->id,
            context: ['purpose' => $challenge->purpose, 'channel' => $challenge->channel],
        ));

        return OtpResult::verified($challenge->id);
    }

    /**
     * Global per-IP verify throttle: the last line against brute-forcing the small
     * numeric code space across many challenges. Returns true when this attempt is
     * over the limit; otherwise counts it.
     */
    private function verifyThrottled(?string $ip): bool
    {
        $key = 'otp:verify:'.($ip ?? 'unknown');

        if ($this->limiter->tooManyAttempts($key, $this->verifyMaxPerWindow)) {
            return true;
        }

        $this->limiter->hit($key, $this->verifyWindowSeconds);

        return false;
    }

    /**
     * Throw if the given issue key is over its cap; the caller charges the key only
     * after every guard has passed, so a rejection never spends another key's budget.
     */
    private function guardIssueThrottle(string $key, int $max): void
    {
        if ($this->limiter->tooManyAttempts($key, $max)) {
            throw new OtpRateLimitExceeded($this->limiter->availableIn($key));
        }
    }

    private function issueKey(string $purpose, string $recipient, ?string $ip): string
    {
        // Hash the recipient so no address (PII) lands in a cache key.
        return 'otp:issue:'.hash('sha256', $purpose.'|'.$recipient).':'.($ip ?? 'unknown');
    }

    /**
     * Purpose- and IP-independent issue key: the anti-bombing cap on how many codes a
     * single recipient can be sent in the window, no matter how the attacker varies
     * the purpose or source IP. Recipient is hashed so no address lands in the key.
     */
    private function issueRecipientKey(string $recipient): string
    {
        return 'otp:issue:recipient:'.hash('sha256', $recipient);
    }

    /**
     * Per-recipient verify throttle for {@see verifyLatest()}: bounds brute-force of a
     * recipient's live challenge across many source IPs. Returns true when over the
     * limit; otherwise counts the attempt.
     */
    private function verifyRecipientThrottled(string $purpose, string $recipient): bool
    {
        $key = 'otp:verify:recipient:'.hash('sha256', $purpose.'|'.$recipient);

        if ($this->limiter->tooManyAttempts($key, $this->verifyPerRecipientMax)) {
            return true;
        }

        $this->limiter->hit($key, $this->verifyWindowSeconds);

        return false;
    }

    private function generateCode(): string
    {
        $max = (10 ** $this->codeLength) - 1;

        return str_pad((string) random_int(0, $max), $this->codeLength, '0', STR_PAD_LEFT);
    }
}
