<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Support;

use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Cbox\Id\Webhooks\ValueObjects\EndpointHealth;
use Illuminate\Support\Carbon;

/**
 * A per-endpoint circuit breaker on the endpoint's own health columns — the
 * direct counterpart of \Cbox\Id\Provisioning\Support\ConnectionCircuitBreaker,
 * which does the same job for outbound SCIM.
 *
 * After `failure_threshold` consecutive failures the breaker OPENS (stamping
 * `circuit_opened_at`) and delivery to THAT endpoint pauses for
 * `cooldown_seconds`. Once the cooldown elapses a single probe is allowed
 * (half-open); a success closes the breaker and resets the count, a failure
 * re-opens it.
 *
 * Why this matters here: without it, every new event to a blackholing receiver
 * paid a fresh 10s Guzzle timeout (5s of it just to fail the connect). The
 * breaker turns "one timeout per event" into "one timeout per cooldown window".
 *
 * Nothing is black-holed: the delivery rows are still written and still retried,
 * they simply wait out the cooldown. Mutations are staged on the model; the
 * caller persists.
 */
class EndpointCircuitBreaker
{
    /** True while the breaker is open and its cooldown has not yet elapsed. */
    public function isOpen(WebhookEndpoint $endpoint): bool
    {
        return $this->closesAt($endpoint)?->isFuture() ?? false;
    }

    /** True when a delivery attempt is permitted (closed, or a half-open probe). */
    public function shouldAttempt(WebhookEndpoint $endpoint): bool
    {
        return ! $this->isOpen($endpoint);
    }

    /** When the open breaker admits its next probe, or null when it is closed. */
    public function closesAt(WebhookEndpoint $endpoint): ?Carbon
    {
        if ($endpoint->circuit_opened_at === null) {
            return null;
        }

        return $endpoint->circuit_opened_at->copy()->addSeconds($this->cooldown());
    }

    public function recordSuccess(WebhookEndpoint $endpoint): void
    {
        $endpoint->consecutive_failures = 0;
        $endpoint->last_success_at = Carbon::now();
        $endpoint->last_error = null;
        $endpoint->circuit_opened_at = null;
    }

    public function recordFailure(WebhookEndpoint $endpoint, ?string $error = null): void
    {
        $endpoint->consecutive_failures += 1;
        $endpoint->last_error = $error;

        if ($endpoint->consecutive_failures >= $this->threshold()) {
            $endpoint->circuit_opened_at = Carbon::now();
        }
    }

    /** A typed snapshot for the console — no column or config knowledge required. */
    public function health(WebhookEndpoint $endpoint): EndpointHealth
    {
        return new EndpointHealth(
            consecutiveFailures: $endpoint->consecutive_failures,
            circuitOpenedAt: $endpoint->circuit_opened_at,
            circuitClosesAt: $this->closesAt($endpoint),
            lastSuccessAt: $endpoint->last_success_at,
            lastError: $endpoint->last_error,
        );
    }

    private function threshold(): int
    {
        $configured = config('cbox-id.webhooks.circuit_breaker.failure_threshold', 5);

        return max(1, is_numeric($configured) ? (int) $configured : 5);
    }

    private function cooldown(): int
    {
        $configured = config('cbox-id.webhooks.circuit_breaker.cooldown_seconds', 300);

        return max(1, is_numeric($configured) ? (int) $configured : 300);
    }
}
