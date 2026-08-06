<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\EmailVerification;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Exceptions\InvalidEmailVerification;
use Cbox\Id\Identity\Models\EmailVerificationToken;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Support\Facades\DB;

class EmailVerificationService implements EmailVerification
{
    private const TTL_MINUTES = 1440; // 24 hours

    public function __construct(
        private readonly Subjects $subjects,
        private readonly AuditLog $audit,
    ) {}

    public function issue(string $subjectId, string $email): string
    {
        $token = 'evf_'.bin2hex(random_bytes(32));

        EmailVerificationToken::query()->create([
            'user_id' => $subjectId,
            'email' => $email,
            'token_hash' => hash('sha256', $token),
            'expires_at' => now()->addMinutes(self::TTL_MINUTES),
        ]);

        $this->audit->record(new AuditEvent(
            action: 'user.email_verification_issued',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $subjectId,
        ));

        return $token;
    }

    public function verify(string $token): string
    {
        return DB::transaction(function () use ($token): string {
            $record = EmailVerificationToken::query()->where('token_hash', hash('sha256', $token))->first();

            if ($record === null || $record->consumed_at !== null || $record->expires_at->isPast()) {
                throw InvalidEmailVerification::make();
            }

            $record->forceFill(['consumed_at' => now()])->save();

            // Stale-address guard lives in the resolver: it no-ops if the subject's
            // current address no longer matches the one this token confirmed.
            $this->subjects->markEmailVerified($record->user_id, $record->email);

            return $record->user_id;
        });
    }
}
