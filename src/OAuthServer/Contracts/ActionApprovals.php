<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Enums\ActionApprovalStatus;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ActionApprovalRequest;

/**
 * Ask a person to approve ONE action before it runs — the human in the loop for an agent
 * holding a credential that may do more than its owner wants it to do unsupervised.
 *
 * Built on the CIBA request store, so the same approval surfaces approve it: a pending
 * action approval appears wherever a CIBA request does, and {@see BackchannelAuthentication::approve()}
 * and `deny()` answer it, bound to the person it was raised for.
 *
 * What it adds is the BINDING. `actionDigest` is the host's hash of exactly what is being
 * approved — the action, its target, its input — and {@see consume()} spends an approval
 * only for that digest and only once, so approving "rotate the secret of Billing" can never
 * be replayed to rotate another app's, or the same one twice. An action approval is never
 * redeemable for tokens at the token endpoint.
 *
 * The package raises `oauth.backchannel_authentication_requested` (with `purpose: action`)
 * exactly as for a CIBA request; notifying the person is the host's.
 */
interface ActionApprovals
{
    /**
     * Ask `$subjectId` to approve the action `$actionDigest` describes, showing them
     * `$bindingMessage`. `$client` is the host's own first-party client the request is
     * filed under (the approval surface names it).
     */
    public function request(Client $client, string $subjectId, string $bindingMessage, string $actionDigest, ?int $ttlSeconds = null): ActionApprovalRequest;

    /** Where the request stands; null when there is no such action approval here. */
    public function status(string $requestId): ?ActionApprovalStatus;

    /**
     * Spend an approval: true exactly once, when it is approved, unexpired, unspent and
     * for this digest. Everything else is false and changes nothing.
     */
    public function consume(string $requestId, string $actionDigest): bool;
}
