<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\PasswordReset;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Exceptions\InvalidPasswordReset;
use Cbox\Id\Identity\Models\PasswordResetToken;
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

            $record->forceFill(['consumed_at' => now()])->save();

            $this->subjects->setPassword($subject->id, $newPassword);

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
