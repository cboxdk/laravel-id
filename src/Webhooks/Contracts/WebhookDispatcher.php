<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Contracts;

interface WebhookDispatcher
{
    /**
     * Deliver an event to every matching endpoint (recording each attempt).
     *
     * @param  array<string, mixed>  $payload
     */
    public function dispatch(string $eventType, array $payload, ?string $organizationId = null): void;

    /**
     * Re-attempt failed deliveries whose backoff window has elapsed. Returns the
     * number re-attempted.
     */
    public function retryPending(int $limit = 50): int;
}
