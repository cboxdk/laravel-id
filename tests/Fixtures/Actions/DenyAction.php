<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures\Actions;

use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;

/** Test in-process action that vetoes the operation. */
final class DenyAction implements Action
{
    public function handle(ActionContext $context): ActionResult
    {
        return ActionResult::deny('blocked by policy');
    }
}
