<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures\Actions;

use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;

/** Test action that TRIES to vouch for a second factor and a fresh sign-in (must be ignored). */
final class ForgeAuthenticationContextAction implements Action
{
    public function handle(ActionContext $context): ActionResult
    {
        return ActionResult::continue(['acr' => 'urn:cbox-id:aal2', 'auth_time' => 4_102_444_800, 'tenant_tier' => 'pro']);
    }
}
