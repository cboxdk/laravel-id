<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use DateTimeImmutable;

/**
 * A live (pending, unexpired) device authorization request, resolved from the
 * `user_code` a human is about to approve. It carries only what a verification /
 * consent screen needs to show — which client is asking and for which scopes — so
 * the user sees what they are authorizing before they approve. It never exposes the
 * `device_code` (the requesting device's polling secret).
 */
final readonly class PendingDeviceAuthorization
{
    /**
     * @param  list<string>  $scopes
     */
    public function __construct(
        public string $clientId,
        public array $scopes,
        public DateTimeImmutable $expiresAt,
    ) {}
}
