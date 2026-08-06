<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Contracts;

interface WebhookDispatcher
{
    /**
     * Record a delivery for every matching endpoint and ENQUEUE it.
     *
     * This never touches the network: it persists the delivery rows and hands
     * each one to the queue, so the caller (the domain-event relay) is never
     * blocked by a slow or dead receiver. The HTTP send happens in
     * {@see deliver()}, on a worker.
     *
     * @param  array<string, mixed>  $payload
     */
    public function dispatch(string $eventType, array $payload, ?string $organizationId = null): void;

    /**
     * Send ONE recorded delivery over HTTP, recording the outcome against the
     * endpoint's circuit breaker. Assumes the delivery's environment is already
     * active. Safe to call twice: a delivery that is already delivered or
     * dead-lettered is a no-op.
     */
    public function deliver(string $deliveryId): void;

    /**
     * Re-enqueue failed deliveries whose backoff window has elapsed. Returns the
     * number enqueued.
     */
    public function retryPending(int $limit = 50): int;
}
