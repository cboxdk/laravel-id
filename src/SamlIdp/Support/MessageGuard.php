<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
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
    // RESOLVED PER CALL, not constructor-injected. Three singletons hold this guard, and
    // a queue worker's `forgetScopedInstances()` unsets the BINDING without touching an
    // object a singleton already holds — so an injected context would pin the first job's
    // tenant for the life of the process, which is worse than the bug below it fixes.
    // `ScopedContextCaptureTest` refuses the injected version by name.
    use ResolvesEnvironment;

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
     *
     * AND ONCE PER ENVIRONMENT. The cache is one namespace across the whole
     * deployment, while an SP EntityID is chosen by the customer — two tenants can
     * legitimately register the same one, and `urn:federation:MicrosoftOnline` is not
     * a hypothetical. Keyed on the SP alone, tenant A claiming a message id makes the
     * SAME id from tenant B's SP look like a replay: their genuine sign-in is refused,
     * and an attacker who can send one message to their own tenant can do it
     * deliberately. The SP-side store learned this already — `consumed_assertions`
     * carries an `environment_id` — and the IdP side never did.
     */
    public function consume(string $scope, string $messageId, int $windowSeconds): bool
    {
        $environment = $this->environments()->current()?->environmentKey() ?? 'none';

        $key = 'cbox:saml:msg:'.hash('sha256', $environment.':'.$scope.':'.$messageId);

        return $this->cache->add($key, true, $windowSeconds * 2);
    }
}
