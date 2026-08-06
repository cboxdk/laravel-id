<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Listeners;

use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Provisioning\Contracts\ProvisioningService;

/**
 * Thin bridge from the domain event bus to outbound provisioning: every delivered
 * event is offered to the {@see ProvisioningService}, which enqueues an outbox
 * operation for each in-scope connection in the current environment (and nothing
 * for events it doesn't map, or when no connection is configured).
 *
 * The listener ONLY enqueues — it never makes a SCIM call on the request thread.
 * It runs inside the delivering environment, so the operations it writes are
 * env-stamped and the drain later reconstructs that same environment.
 */
class ProvisionOnDomainEvent
{
    public function __construct(private readonly ProvisioningService $provisioning) {}

    public function handle(EventDelivered $delivered): void
    {
        $this->provisioning->enqueueForEvent(
            $delivered->event->type,
            $delivered->event->payload,
            $delivered->event->organization_id,
        );
    }
}
