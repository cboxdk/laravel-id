<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\MagicLink;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Exceptions\InvalidMagicLink;
use Cbox\Id\Identity\Models\MagicLinkToken;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Support\Facades\DB;

class MagicLinkService implements MagicLink
{
    private const TTL_MINUTES = 15;

    public function __construct(
        private readonly Subjects $subjects,
        private readonly SessionManager $sessions,
        private readonly AuditLog $audit,
    ) {}

    public function request(string $email): string
    {
        $token = 'ml_'.bin2hex(random_bytes(32));

        MagicLinkToken::query()->create([
            'email' => $email,
            'token_hash' => hash('sha256', $token),
            'expires_at' => now()->addMinutes(self::TTL_MINUTES),
        ]);

        $this->audit->record(new AuditEvent(
            action: 'user.magic_link_requested',
            actorType: ActorType::System,
            targetType: 'email',
            targetId: $email,
        ));

        return $token;
    }

    public function redeem(string $token): Session
    {
        return DB::transaction(function () use ($token): Session {
            $link = MagicLinkToken::query()->where('token_hash', hash('sha256', $token))->lockForUpdate()->first();

            if ($link === null || $link->consumed_at !== null || $link->expires_at->isPast()) {
                throw InvalidMagicLink::make();
            }

            $link->forceFill(['consumed_at' => now()])->save();

            $subject = $this->subjects->findByEmail($link->email) ?? $this->subjects->create($link->email);

            // A deactivated account can't be logged in via a magic link either.
            if (! $this->subjects->isActive($subject->id)) {
                throw InvalidMagicLink::make();
            }

            $session = $this->sessions->start($subject->id, null, ['magic_link']);

            $this->audit->record(new AuditEvent(
                action: 'user.login',
                actorType: ActorType::User,
                actorId: $subject->id,
                targetType: 'session',
                targetId: $session->id,
                context: ['method' => 'magic_link'],
            ));

            return $session;
        });
    }
}
