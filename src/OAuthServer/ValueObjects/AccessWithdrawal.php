<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * A person's access to one or more applications has been withdrawn — their grants were
 * revoked, their membership was removed — and the applications should end the sessions
 * they hold for them.
 *
 * Narrowed by `organizationId` (only what was granted in that organization) and/or
 * `clientId` (only that application). With neither, it is the whole subject.
 *
 * `grants` names clients known to hold a grant that the recorded sessions may not cover —
 * the refresh tokens just revoked, typically — so they are notified even when no
 * participation row exists for them.
 */
readonly class AccessWithdrawal
{
    /**
     * @param  list<SessionParticipation>  $grants
     */
    public function __construct(
        public string $userId,
        public ?string $organizationId = null,
        public ?string $clientId = null,
        public array $grants = [],
    ) {}

    /**
     * Whether this withdraws everything the person holds, rather than one organization's
     * or one application's share of it.
     */
    public function isSubjectWide(): bool
    {
        return $this->organizationId === null && $this->clientId === null;
    }
}
