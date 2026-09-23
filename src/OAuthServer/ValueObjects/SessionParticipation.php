<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * One relying party a person was signed in to, and — when known — from which sign-in
 * session.
 *
 * `sessionId` is null for a grant that was not issued from a session (a device or CIBA
 * approval, or anything issued before sessions were recorded). A logout can still reach
 * such a client by `sub`, but never by `sid`.
 */
readonly class SessionParticipation
{
    public function __construct(
        public string $clientId,
        public string $userId,
        public ?string $sessionId = null,
        public ?string $organizationId = null,
    ) {}
}
