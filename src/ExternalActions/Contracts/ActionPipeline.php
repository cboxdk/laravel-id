<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Contracts;

use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\PipelineOutcome;

/**
 * Runs every action registered at a hook point — in-process handlers
 * ({@see ActionRegistry}) and external HTTP endpoints ({@see ExternalActions}) — and
 * folds their results into a single {@see PipelineOutcome}. The first deny
 * short-circuits (the operation is vetoed); otherwise the enrichment from each
 * continuing action is merged.
 *
 * When a hook point has no actions at all, the outcome is a cheap allow-with-no-
 * enrichment — so a caller can invoke the pipeline unconditionally on a hot path.
 */
interface ActionPipeline
{
    public function run(HookPoint $hookPoint, ActionContext $context): PipelineOutcome;
}
