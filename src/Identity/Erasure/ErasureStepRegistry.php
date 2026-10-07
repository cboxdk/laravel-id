<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Erasure;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\Contracts\ErasureSteps;

/**
 * The default {@see ErasureSteps}: an in-process list filled by service providers at
 * boot. Keyed by step name, so a host can replace a package step by registering its
 * own under the same name.
 */
class ErasureStepRegistry implements ErasureSteps
{
    /** @var array<string, ErasureStep> */
    private array $steps = [];

    public function register(ErasureStep $step): void
    {
        $this->steps[$step->name()] = $step;
    }

    public function all(): array
    {
        return array_values($this->steps);
    }
}
