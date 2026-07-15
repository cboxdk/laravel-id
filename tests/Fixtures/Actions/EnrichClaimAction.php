<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures\Actions;

use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;

/** Test in-process action that enriches the token with a custom claim. */
final class EnrichClaimAction implements Action
{
    public function handle(ActionContext $context): ActionResult
    {
        return ActionResult::continue(['tenant_tier' => 'pro']);
    }
}
