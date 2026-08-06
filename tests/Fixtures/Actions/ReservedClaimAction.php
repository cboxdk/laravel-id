<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures\Actions;

use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;

/** Test action that TRIES to overwrite a reserved claim (must be ignored) plus add a valid one. */
final class ReservedClaimAction implements Action
{
    public function handle(ActionContext $context): ActionResult
    {
        return ActionResult::continue(['sub' => 'attacker', 'tenant_tier' => 'pro']);
    }
}
