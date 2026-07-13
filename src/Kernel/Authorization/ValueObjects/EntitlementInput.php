<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;

/**
 * The desired state of a single entitlement, as pushed from a source of truth.
 */
final readonly class EntitlementInput
{
    /**
     * @param  array<string, mixed>  $value  e.g. {"tier":"pro"} / {"limit":50} / {"enabled":true}
     */
    public function __construct(
        public string $key,
        public array $value,
        // Live by default — instant on change, no token staleness. Opt into
        // `Claims` for coarse, slow-changing keys you want embedded in the token.
        public EnforcementMode $mode = EnforcementMode::DecisionApi,
    ) {}
}
