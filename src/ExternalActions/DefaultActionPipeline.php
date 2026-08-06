<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions;

use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\ExternalActions\Contracts\ActionRegistry;
use Cbox\Id\ExternalActions\Contracts\ActionTransport;
use Cbox\Id\ExternalActions\Contracts\ConcurrentActionTransport;
use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Cbox\Id\ExternalActions\Enums\FailPolicy;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;
use Cbox\Id\ExternalActions\ValueObjects\PipelineOutcome;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Support\Collection;
use Throwable;

/**
 * Runs a hook point's in-process handlers, then its external endpoints, folding the
 * results. The first deny short-circuits and is audited; enrichment from continuing
 * actions is merged in order (later wins). A hook point with no actions is a cheap
 * allow, so callers invoke it unconditionally.
 *
 * Two things are decided per HOOK POINT rather than globally:
 *
 *  - {@see FailPolicy} — what an action that could not be CONSULTED means here. An
 *    in-process handler that throws, or an endpoint that timed out, is a deny at a
 *    fail-closed point and a skip at a fail-open one. An explicit deny is never
 *    affected.
 *  - {@see HookPoint::vetoable()} — whether a deny can stop anything at all. At a
 *    `post_*` point the operation has already committed, so a deny is audited (it
 *    stays visible) and then folded to an allow here, centrally, instead of every
 *    call site having to remember to ignore the outcome.
 */
class DefaultActionPipeline implements ActionPipeline
{
    public function __construct(
        private readonly ActionRegistry $registry,
        private readonly ExternalActions $endpoints,
        private readonly ActionTransport $transport,
        private readonly AuditLog $audit,
    ) {}

    public function run(HookPoint $hookPoint, ActionContext $context): PipelineOutcome
    {
        $enrichment = [];

        foreach ($this->registry->for($hookPoint) as $action) {
            $result = $this->runInProcess($action, $hookPoint, $context);

            if (! $result->allowed) {
                $veto = $this->denied($hookPoint, $context, $result->reason, 'in_process');

                // A veto stops the pipeline. At a non-vetoable point `denied()` has
                // audited and returned an allow instead — the remaining actions were
                // not the ones being refused, so they still run.
                if (! $veto->allowed) {
                    return $veto;
                }

                continue;
            }

            $enrichment = array_merge($enrichment, $result->enrichment);
        }

        // Scope the fan-out to the org this run is FOR, so a tenant's hook only ever sees
        // its own tenant's context (plus the environment's own hooks, which apply to all).
        $endpoints = $this->endpoints->active($hookPoint, $context->string('organization_id'));

        foreach ($this->results($hookPoint, $endpoints, $context) as $endpointId => $result) {
            if (! $result->allowed) {
                $veto = $this->denied($hookPoint, $context, $result->reason, 'external:'.$endpointId);

                if (! $veto->allowed) {
                    return $veto;
                }

                continue;
            }

            $enrichment = array_merge($enrichment, $result->enrichment);
        }

        return PipelineOutcome::allow($enrichment);
    }

    /**
     * Each endpoint's reply, in REGISTRATION ORDER — so the first deny still wins and
     * enrichment still folds later-over-earlier, whether the calls were made one at a
     * time or all at once.
     *
     * More than one endpoint goes out concurrently when the transport supports it.
     * Sequentially, each hook costs a connect timeout plus a read timeout on the token
     * path, so three hooks tripled that budget on every single mint; pooled, the whole
     * fan-out costs one endpoint's budget. A single endpoint takes the plain path,
     * because there is nothing to overlap and the sequential call is one fewer moving
     * part.
     *
     * @param  Collection<int, ExternalActionEndpoint>  $endpoints
     * @return array<string, ActionResult>
     */
    private function results(HookPoint $hookPoint, Collection $endpoints, ActionContext $context): array
    {
        if ($endpoints->count() > 1 && $this->transport instanceof ConcurrentActionTransport) {
            $byId = $this->transport->sendMany($endpoints, $context);

            $ordered = [];

            foreach ($endpoints as $endpoint) {
                // A transport that omitted an endpoint has not answered for it, and at a
                // fail-closed point an unanswered security hook must not read as an allow.
                $ordered[$endpoint->id] = $byId[$endpoint->id] ?? $this->unavailable($hookPoint);
            }

            return $ordered;
        }

        $results = [];

        foreach ($endpoints as $endpoint) {
            $result = $this->transport->send($endpoint, $context);
            $results[$endpoint->id] = $result;

            // The sequential path keeps its short-circuit: a denied operation must not
            // go on to call endpoints that had no say in the decision. A non-vetoable
            // point has no decision to short-circuit, so every endpoint is still told.
            if (! $result->allowed && $hookPoint->vetoable()) {
                break;
            }
        }

        return $results;
    }

    private function runInProcess(Action $action, HookPoint $hookPoint, ActionContext $context): ActionResult
    {
        try {
            return $action->handle($context);
        } catch (Throwable) {
            // A handler that threw was not consulted — same class of event as an
            // endpoint that timed out, so it answers to the same per-hook policy.
            return FailPolicy::for($hookPoint)->isOpen()
                ? ActionResult::continue()
                : ActionResult::deny('in-process action failed');
        }
    }

    /**
     * An action that could not be consulted, resolved through the hook point's fail
     * policy.
     */
    private function unavailable(HookPoint $hookPoint): ActionResult
    {
        return FailPolicy::for($hookPoint)->isOpen()
            ? ActionResult::continue()
            : ActionResult::deny('external action unavailable');
    }

    /**
     * Record the veto and produce the outcome.
     *
     * At a non-vetoable point the audit still happens — an endpoint denying a
     * `post_*` hook is a real signal, usually a misconfiguration on the receiver's
     * side, and swallowing it would leave the operator no way to see it — but the
     * outcome is an allow, because the operation it would veto has already committed.
     */
    private function denied(HookPoint $hookPoint, ActionContext $context, string $reason, string $by): PipelineOutcome
    {
        // Audit the veto with the hook, the deciding action and the actors — never the
        // enrichment/claim values.
        $this->audit->record(new AuditEvent(
            action: 'external_action.denied',
            actorType: ActorType::System,
            organizationId: $context->string('organization_id'),
            targetType: 'external_action_hook',
            targetId: $hookPoint->value,
            context: [
                'reason' => $reason,
                'by' => $by,
                'vetoable' => $hookPoint->vetoable(),
                'client_id' => $context->string('client_id'),
                // Points other than token_minting name the principal `user_id`; fall
                // back so the audit trail names WHO was denied at every hook point.
                'subject' => $context->string('subject') ?? $context->string('user_id'),
            ],
        ));

        return $hookPoint->vetoable() ? PipelineOutcome::deny($reason) : PipelineOutcome::allow();
    }
}
