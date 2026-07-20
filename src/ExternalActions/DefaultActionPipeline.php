<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions;

use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\ExternalActions\Contracts\ActionRegistry;
use Cbox\Id\ExternalActions\Contracts\ActionTransport;
use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;
use Cbox\Id\ExternalActions\ValueObjects\PipelineOutcome;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Throwable;

/**
 * Runs a hook point's in-process handlers, then its external endpoints, folding the
 * results. The first deny short-circuits and is audited; enrichment from continuing
 * actions is merged in order (later wins). A hook point with no actions is a cheap
 * allow, so callers invoke it unconditionally.
 *
 * Fail-closed: an in-process handler that throws is treated as a deny (unless
 * `external_actions.fail_open`); the transport enforces the same policy for external
 * calls internally.
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
            $result = $this->runInProcess($action, $context);

            if (! $result->allowed) {
                return $this->denied($hookPoint, $context, $result->reason, 'in_process');
            }

            $enrichment = array_merge($enrichment, $result->enrichment);
        }

        // Scope the fan-out to the org this run is FOR, so a tenant's hook only ever sees
        // its own tenant's context (plus the environment's own hooks, which apply to all).
        foreach ($this->endpoints->active($hookPoint, $context->string('organization_id')) as $endpoint) {
            $result = $this->transport->send($endpoint, $context);

            if (! $result->allowed) {
                return $this->denied($hookPoint, $context, $result->reason, 'external:'.$endpoint->id);
            }

            $enrichment = array_merge($enrichment, $result->enrichment);
        }

        return PipelineOutcome::allow($enrichment);
    }

    private function runInProcess(Action $action, ActionContext $context): ActionResult
    {
        try {
            return $action->handle($context);
        } catch (Throwable) {
            return config('cbox-id.external_actions.fail_open', false) === true
                ? ActionResult::continue()
                : ActionResult::deny('in-process action failed');
        }
    }

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
                'client_id' => $context->string('client_id'),
                'subject' => $context->string('subject'),
            ],
        ));

        return PipelineOutcome::deny($reason);
    }
}
