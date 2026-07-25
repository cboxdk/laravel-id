<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\PasswordPolicyGuard;
use Cbox\Id\Identity\Contracts\PasswordReset;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Exceptions\InvalidPasswordReset;
use Cbox\Id\Identity\Models\PasswordResetToken;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Support\Facades\DB;

class PasswordResetService implements PasswordReset
{
    private const TTL_MINUTES = 60;

    public function __construct(
        private readonly Subjects $subjects,
        private readonly SessionManager $sessions,
        private readonly PasswordPolicyGuard $policy,
        private readonly AuditLog $audit,
    ) {}

    public function request(string $email): ?string
    {
        // Only mint a token for a real account; the controller shows an identical
        // message regardless, so this null does not leak account existence.
        if ($this->subjects->findByEmail($email) === null) {
            return null;
        }

        $token = 'pwr_'.bin2hex(random_bytes(32));

        PasswordResetToken::query()->create([
            'email' => $email,
            'token_hash' => hash('sha256', $token),
            'expires_at' => now()->addMinutes(self::TTL_MINUTES),
        ]);

        $this->audit->record(new AuditEvent(
            action: 'user.password_reset_requested',
            actorType: ActorType::System,
            targetType: 'email',
            targetId: $email,
        ));

        return $token;
    }

    /** Retain the stored hash so a reuse policy can compare against what auth will check. */
    private function rememberForReuse(string $subjectId): void
    {
        $hash = User::query()->whereKey($subjectId)->value('password');

        if (is_string($hash) && $hash !== '') {
            $this->policy->remember($subjectId, $hash);
        }
    }

    public function reset(string $token, string $newPassword): void
    {
        DB::transaction(function () use ($token, $newPassword): void {
            $record = PasswordResetToken::query()->where('token_hash', hash('sha256', $token))->first();

            if ($record === null || $record->consumed_at !== null || $record->expires_at->isPast()) {
                throw InvalidPasswordReset::make();
            }

            $subject = $this->subjects->findByEmail($record->email);

            if ($subject === null) {
                throw InvalidPasswordReset::make();
            }

            // CLAIM the token with a conditional update rather than a read-then-write:
            // two requests presenting the same token concurrently would both have seen
            // `consumed_at` null above and both gone on to set a password. Only the
            // update that actually matches an unconsumed row wins; the loser is refused,
            // so a single-use token is single-use under real concurrency.
            $claimed = PasswordResetToken::query()
                ->whereKey($record->id)
                ->whereNull('consumed_at')
                ->update(['consumed_at' => now()]);

            if ($claimed !== 1) {
                throw InvalidPasswordReset::make();
            }

            // The tenant's policy binds the SELF-SERVICE path too. Enforcing it only on
            // administrative assignment left the door most people actually use governed by
            // whatever floor the calling form happened to hardcode — so an environment
            // demanding 24 characters got 12 here, silently.
            $this->policy->assertAcceptable($newPassword, $subject->id);

            $this->subjects->setPassword($subject->id, $newPassword);

            // Record the new hash, or the reuse policy compares against a history that
            // only ever contained administrative assignments — i.e. never the passwords
            // the subject actually chose.
            $this->rememberForReuse($subject->id);

            // A reset implies the previous credential may be compromised — cut every
            // existing session so a thief can't ride one past the change.
            $this->sessions->revokeAllForUser($subject->id);

            // Any other outstanding reset tokens for this account are now void.
            PasswordResetToken::query()
                ->where('email', $record->email)
                ->whereNull('consumed_at')
                ->update(['consumed_at' => now()]);

            $this->audit->record(new AuditEvent(
                action: 'user.password_reset',
                actorType: ActorType::User,
                actorId: $subject->id,
                targetType: 'user',
                targetId: $subject->id,
            ));
        });
    }
}
