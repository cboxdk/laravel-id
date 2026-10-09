<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures\Actions;

use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;

/** Test in-process action that tries to write its own `feature_flags` claim. */
final class FeatureFlagsClaimAction implements Action
{
    public function handle(ActionContext $context): ActionResult
    {
        return ActionResult::continue(['feature_flags' => ['forged-by-hook']]);
    }
}
