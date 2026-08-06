<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Payloads;

use Cbox\Id\ExternalActions\Contracts\HookPayload;
use Cbox\Id\ExternalActions\Enums\HookPoint;

/**
 * What a registration hook sees, on both sides of subject creation. One class for
 * both points because it is one operation observed twice; the only difference is
 * `user_id`, which cannot exist before the account does.
 *
 *  - {@see before()} → {@see HookPoint::PreRegistration}, `user_id` null. A deny here
 *    means no account is created.
 *  - {@see after()} → {@see HookPoint::PostRegistration}, `user_id` set.
 *
 * `has_password` says whether the account is being created WITH a credential — the
 * difference between a self-serve signup and a just-in-time provision from SSO,
 * directory sync or an invitation. The password itself is never included.
 */
final readonly class RegistrationPayload implements HookPayload
{
    private function __construct(
        private HookPoint $hookPoint,
        public string $email,
        public ?string $name,
        public ?string $userId,
        public bool $hasPassword,
    ) {}

    public static function before(string $email, ?string $name, bool $hasPassword): self
    {
        return new self(HookPoint::PreRegistration, $email, $name, null, $hasPassword);
    }

    public static function after(string $userId, string $email, ?string $name, bool $hasPassword): self
    {
        return new self(HookPoint::PostRegistration, $email, $name, $userId, $hasPassword);
    }

    public function hookPoint(): HookPoint
    {
        return $this->hookPoint;
    }

    public function toPayload(): array
    {
        return [
            'user_id' => $this->userId,
            'email' => $this->email,
            'name' => $this->name,
            'has_password' => $this->hasPassword,
        ];
    }
}
