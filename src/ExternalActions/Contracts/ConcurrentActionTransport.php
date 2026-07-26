<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Contracts;

use Cbox\Id\ExternalActions\DefaultActionPipeline;
use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;
use Illuminate\Support\Collection;

/**
 * A transport that can call several endpoints AT ONCE.
 *
 * Hook endpoints are called synchronously, in the request, with a connect timeout
 * plus a read timeout each. Called one after another, three configured hooks add up
 * to three times that budget to every single token mint — serially, and fail-closed,
 * so `/oauth/token` p99 grew with the number of hooks a tenant had registered.
 * Concurrently, the whole fan-out costs one endpoint's timeout no matter how many
 * there are.
 *
 * Deliberately a SEPARATE interface rather than a method on {@see ActionTransport}:
 * a host that has substituted its own transport keeps working unchanged, and
 * {@see DefaultActionPipeline} falls back to sequential
 * sends when the bound transport does not offer this.
 *
 * SEMANTIC DIFFERENCE, stated plainly: sequentially, the first denying endpoint
 * short-circuits and later endpoints are never called. Concurrently, every endpoint
 * in the fan-out is called before any reply is read, so a hook can now observe a
 * context for an operation that another hook vetoed. The DECISION is unchanged — the
 * first deny in registration order still wins, and enrichment is still folded in
 * registration order — but a hook with side effects sees strictly more calls.
 */
interface ConcurrentActionTransport extends ActionTransport
{
    /**
     * @param  Collection<int, ExternalActionEndpoint>  $endpoints
     * @return array<string, ActionResult> keyed by endpoint id; every endpoint passed
     *                                     in is present in the result
     */
    public function sendMany(Collection $endpoints, ActionContext $context): array;
}
