<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Contracts;

use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;

/**
 * An in-process action: a host-provided handler that runs synchronously at a hook
 * point. Return {@see ActionResult::continue()} (optionally with enrichment) to
 * allow, or {@see ActionResult::deny()} to veto. Register your class in
 * `cbox-id.external_actions.hooks.<point>` — the registry is deny-by-default, so
 * only listed classes run.
 *
 * This is the dependency-light alternative to an external HTTP endpoint: use it when
 * you'd rather run code in the app than call out over the network.
 */
interface Action
{
    public function handle(ActionContext $context): ActionResult;
}
