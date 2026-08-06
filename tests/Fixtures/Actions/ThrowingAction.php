<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures\Actions;

use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;
use RuntimeException;

/** Test action that throws, to exercise the fail-closed / fail-open policy. */
final class ThrowingAction implements Action
{
    public function handle(ActionContext $context): ActionResult
    {
        throw new RuntimeException('boom');
    }
}
