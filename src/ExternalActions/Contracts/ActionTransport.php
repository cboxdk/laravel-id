<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Contracts;

use Cbox\Id\ExternalActions\HttpActionTransport;
use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;

/**
 * Sends a hook request to a registered external endpoint and interprets its reply.
 * The default {@see HttpActionTransport} POSTs a signed,
 * SSRF-guarded, short-timeout request (no redirects, no retry, TLS verify on) and
 * fails CLOSED — any transport error, non-2xx, or unsafe target becomes a deny. A
 * fake transport ships for tests so the pipeline never touches the network.
 */
interface ActionTransport
{
    public function send(ExternalActionEndpoint $endpoint, ActionContext $context): ActionResult;
}
