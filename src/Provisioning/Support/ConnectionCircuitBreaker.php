<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Support;

use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Illuminate\Support\Carbon;

/**
 * A per-connection circuit breaker built on the connection's health columns.
 * After `failure_threshold` consecutive TRANSIENT failures the breaker OPENS
 * (stamping `circuit_opened_at`) and the drain pauses that connection for
 * `cooldown_seconds`. Once the cooldown elapses a single probe is allowed
 * (half-open); a success closes the breaker and resets the count, a failure
 * re-opens it.
 *
 * The breaker isolates a faulty downstream app — every OTHER connection keeps
 * delivering — but never black-holes: failures are always counted and the state
 * is visible on the model. Mutations are staged on the model; the caller persists.
 * Mirrors the proven laravel-siem breaker, on this module's own columns.
 */
class ConnectionCircuitBreaker
{
    /** True while the breaker is open and its cooldown has not yet elapsed. */
    public function isOpen(ProvisioningConnection $connection): bool
    {
        if ($connection->circuit_opened_at === null) {
            return false;
        }

        return $connection->circuit_opened_at->copy()->addSeconds($this->cooldown())->isFuture();
    }

    /** True when a delivery attempt is permitted (closed, or a half-open probe). */
    public function shouldAttempt(ProvisioningConnection $connection): bool
    {
        return ! $this->isOpen($connection);
    }

    public function recordSuccess(ProvisioningConnection $connection): void
    {
        $connection->consecutive_failures = 0;
        $connection->last_success_at = Carbon::now();
        $connection->circuit_opened_at = null;
    }

    public function recordFailure(ProvisioningConnection $connection, ?string $error = null): void
    {
        $connection->consecutive_failures += 1;
        $connection->last_error = $error;

        if ($connection->consecutive_failures >= $this->threshold()) {
            $connection->circuit_opened_at = Carbon::now();
        }
    }

    private function threshold(): int
    {
        $configured = config('cbox-id.provisioning.circuit_breaker.failure_threshold', 5);

        return max(1, is_numeric($configured) ? (int) $configured : 5);
    }

    private function cooldown(): int
    {
        $configured = config('cbox-id.provisioning.circuit_breaker.cooldown_seconds', 300);

        return max(1, is_numeric($configured) ? (int) $configured : 300);
    }
}
