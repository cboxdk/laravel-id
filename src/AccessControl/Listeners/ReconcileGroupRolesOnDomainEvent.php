<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Listeners;

use Cbox\Id\AccessControl\Contracts\GroupRoleMappings;
use Cbox\Id\Kernel\Events\EventDelivered;

/**
 * When a directory group's membership changes (SCIM create/replace/patch/delete),
 * reconcile its group→role assignments. Decoupled via the domain-event outbox — the
 * Directory layer emits, this AccessControl listener reacts — so the dependency runs
 * one way (AccessControl → Directory) with no cycle.
 */
class ReconcileGroupRolesOnDomainEvent
{
    public function __construct(private readonly GroupRoleMappings $mappings) {}

    public function handle(EventDelivered $delivered): void
    {
        $event = $delivered->event;

        if ($event->type !== 'directory.group.membership_changed') {
            return;
        }

        $groupId = $event->payload['group_id'] ?? null;
        $organizationId = $event->payload['organization_id'] ?? null;

        if (is_string($groupId)) {
            $this->mappings->reconcileGroup($groupId, is_string($organizationId) ? $organizationId : null);
        }
    }
}
