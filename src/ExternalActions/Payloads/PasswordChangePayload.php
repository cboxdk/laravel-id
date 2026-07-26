<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Payloads;

use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\Contracts\HookPayload;
use Cbox\Id\ExternalActions\Enums\HookPoint;

/**
 * What a password-change hook sees, on both sides of the credential write:
 *
 *  - {@see before()} → {@see HookPoint::PrePasswordChange}. A deny means the
 *    credential is not written and the caller's change fails.
 *  - {@see after()} → {@see HookPoint::PostPasswordChange}, the notification.
 *
 * The payload names the SUBJECT and nothing else. The plaintext password, the hash,
 * and any derivative of either are deliberately absent: a hook is an outbound HTTP
 * call to a customer-controlled URL, and no password policy is worth putting
 * credential material on that wire. A check that genuinely needs the plaintext (a
 * corporate dictionary, a breach corpus) belongs in an in-process {@see Action} or
 * behind the Identity module's `BreachedPasswordCheck`, both of which run in the
 * app's own memory.
 */
final readonly class PasswordChangePayload implements HookPayload
{
    private function __construct(
        private HookPoint $hookPoint,
        public string $userId,
    ) {}

    public static function before(string $userId): self
    {
        return new self(HookPoint::PrePasswordChange, $userId);
    }

    public static function after(string $userId): self
    {
        return new self(HookPoint::PostPasswordChange, $userId);
    }

    public function hookPoint(): HookPoint
    {
        return $this->hookPoint;
    }

    public function toPayload(): array
    {
        return ['user_id' => $this->userId];
    }
}
