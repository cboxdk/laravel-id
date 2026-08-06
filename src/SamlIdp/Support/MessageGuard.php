<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use Illuminate\Contracts\Cache\Repository as Cache;

/**
 * The freshness + single-use guard every inbound SAML protocol message goes
 * through. A valid signature proves WHO sent a message, never WHEN or HOW OFTEN:
 * without this, a captured `LogoutRequest` force-logs-a-user-out at any later
 * time, and a captured `AuthnRequest` mints a second assertion for a login the
 * user performed once.
 *
 * Both halves fail closed — an absent or unparseable `IssueInstant` is stale, and
 * an id that cannot be claimed is a replay.
 */
class MessageGuard
{
    public function __construct(private readonly Cache $cache) {}

    /**
     * Whether `$issueInstant` is within `$windowSeconds` of now in BOTH directions
     * (a message from the future is as suspect as one from the past, and modest
     * clock skew between IdP and SP is normal).
     */
    public function fresh(?string $issueInstant, int $windowSeconds): bool
    {
        if ($issueInstant === null || $issueInstant === '') {
            return false;
        }

        $instant = strtotime($issueInstant);

        return $instant !== false && abs(time() - $instant) <= $windowSeconds;
    }

    /**
     * Claim a message id ONCE within `$scope` (the sending SP, so two SPs cannot
     * collide or burn each other's ids). Returns false when it was already
     * claimed — that is the replay. Held for twice the freshness window so a
     * replay arriving while the message is still "fresh" is still caught.
     */
    public function consume(string $scope, string $messageId, int $windowSeconds): bool
    {
        $key = 'cbox:saml:msg:'.hash('sha256', $scope.':'.$messageId);

        return $this->cache->add($key, true, $windowSeconds * 2);
    }
}
