<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Contracts;

/**
 * Translates a platform domain change into SCIM operations and drives their
 * durable, at-least-once delivery to downstream apps.
 *
 * The request thread only ENQUEUES ({@see enqueueForEvent()}); a queued
 * per-connection worker DRAINS ({@see drainConnection()}). This split is what
 * keeps provisioning off the request path and lets a worker reconstruct the
 * connection's environment before touching any scoped data.
 */
interface ProvisioningService
{
    /**
     * Translate a delivered domain event into outbox operations — one per
     * in-scope connection in the CURRENT environment. Unknown event types and
     * out-of-scope subjects enqueue nothing. Returns the number enqueued.
     *
     * @param  array<string, mixed>  $payload
     */
    public function enqueueForEvent(string $eventType, array $payload, ?string $organizationId): int;

    /**
     * Drain the pending outbox for one connection, delivering each operation to
     * its downstream app (stateful create/update/deactivate, reconciling 409/404),
     * with bounded backoff, a dead-letter cap and the per-connection circuit
     * breaker. Assumes the connection's environment is already active. Returns the
     * number delivered.
     */
    public function drainConnection(string $connectionId): int;

    /**
     * Full reconcile: enqueue an upsert for every in-scope subject of the
     * connection (create missing remote records, update existing ones). Assumes
     * the connection's environment is already active. Returns the number enqueued.
     */
    public function reconcileConnection(string $connectionId): int;
}
