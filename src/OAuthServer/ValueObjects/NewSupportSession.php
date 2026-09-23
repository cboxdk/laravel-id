<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Enums\SupportActorKind;

/**
 * A request to act as one person, in one organization, in one app.
 */
readonly class NewSupportSession
{
    /**
     * @param  list<string>  $scopes  what the session's codes carry; narrowed to the
     *                                client's registered scopes, never `offline_access`.
     *                                Empty means the client's registered set.
     */
    public function __construct(
        public string $actorId,
        public SupportActorKind $actorKind,
        public string $targetUserId,
        public string $organizationId,
        public string $clientId,
        public string $reason,
        public array $scopes = [],

        /**
         * Requested lifetime in seconds, or null for the configured maximum. Never longer
         * than `cbox-id.oauth.support_sessions.max_ttl`, which itself never exceeds an
         * hour.
         */
        public ?int $ttlSeconds = null,
    ) {}
}
