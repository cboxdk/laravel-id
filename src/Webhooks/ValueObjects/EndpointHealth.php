<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\ValueObjects;

use Illuminate\Support\Carbon;

/**
 * The circuit-breaker state of one endpoint, as a typed snapshot the console can
 * render without knowing the breaker's config or column layout.
 *
 * `EndpointStatus` stays the operator's INTENT (active/paused). This is HEALTH:
 * it moves on its own as deliveries succeed and fail, and clears itself once the
 * cooldown elapses.
 */
final readonly class EndpointHealth
{
    public function __construct(
        public int $consecutiveFailures,
        public ?Carbon $circuitOpenedAt,
        public ?Carbon $circuitClosesAt,
        public ?Carbon $lastSuccessAt,
        public ?string $lastError,
    ) {}

    /** True while the breaker is open and its cooldown has not yet elapsed. */
    public function isTripped(): bool
    {
        return $this->circuitClosesAt !== null && $this->circuitClosesAt->isFuture();
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'tripped' => $this->isTripped(),
            'consecutive_failures' => $this->consecutiveFailures,
            'circuit_opened_at' => $this->circuitOpenedAt?->toIso8601String(),
            'circuit_closes_at' => $this->circuitClosesAt?->toIso8601String(),
            'last_success_at' => $this->lastSuccessAt?->toIso8601String(),
            'last_error' => $this->lastError,
        ];
    }
}
