<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\MagicLink;
use Cbox\Id\Identity\Contracts\MailboxProof;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\SignInMethods;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Exceptions\InvalidMagicLink;
use Cbox\Id\Identity\Exceptions\SignInMethodDisabled;
use Cbox\Id\Identity\Models\MagicLinkToken;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\SecretPrefix;
use Illuminate\Support\Facades\DB;

/**
 * One-time sign-in links: minted, mailed by the host, redeemed once.
 *
 * REFUSED WHERE THE METHOD IS OFF ({@see SignInMethods::magicLinkEnabled()}), on both
 * halves: no link is minted, and a link minted before the switch was turned off no longer
 * redeems — turning magic links off is meant to close the door, not to stop new keys being
 * cut for it while the old ones still work.
 *
 * A REDEEMED LINK PROVES THE MAILBOX. When it lands on an account whose address was never
 * verified, the account is handed to the link's holder through {@see MailboxProof} before
 * the session starts: whatever was set on it before (password, factors, passkeys, linked
 * sign-ins, tokens, sessions) is withdrawn and the address is marked verified. A verified
 * account is signed in to as it is.
 */
class MagicLinkService implements MagicLink
{
    private const TTL_MINUTES = 15;

    public function __construct(
        private readonly Subjects $subjects,
        private readonly SessionManager $sessions,
        private readonly AuditLog $audit,
        private readonly ?MailboxProof $mailboxProof = null,
    ) {}

    /**
     * Refused with {@see SignInMethodDisabled} when magic links are off here.
     */
    public function request(string $email): string
    {
        $this->assertEnabled();

        $token = SecretPrefix::MagicLink->mint();

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

    /**
     * Refused with {@see SignInMethodDisabled} when magic links are off here.
     */
    public function redeem(string $token): Session
    {
        $this->assertEnabled();

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

            // Before the session starts, so the only session left on a claimed account is
            // the one this link opens.
            if (! $subject->emailVerified) {
                $subject = ($this->mailboxProof ?? app(MailboxProof::class))->claim($subject, $link->email);
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

    /**
     * Resolved per call rather than injected, so this service's constructor stays what hosts
     * already build it with.
     */
    private function assertEnabled(): void
    {
        if (app()->bound(SignInMethods::class) && ! app(SignInMethods::class)->magicLinkEnabled()) {
            throw SignInMethodDisabled::make('magic_link');
        }
    }
}
