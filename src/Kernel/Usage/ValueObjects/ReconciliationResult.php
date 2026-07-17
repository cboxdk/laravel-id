<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage\ValueObjects;

/**
 * The outcome of reconciling one org's usage against ground truth: what the meter
 * said (`metered`), what reality said (`expected`), the gap (`drift`), and whether a
 * correction was applied. `drift === 0` means the meter was already truthful.
 */
final readonly class ReconciliationResult
{
    public function __construct(
        public string $organizationId,
        public string $dimension,
        public int $expected,
        public int $metered,
        public int $drift,
        public bool $corrected,
    ) {}

    public function driftDetected(): bool
    {
        return $this->drift !== 0;
    }
}
