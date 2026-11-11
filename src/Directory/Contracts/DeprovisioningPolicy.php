<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Contracts;

use Cbox\Id\Directory\Enums\DeprovisioningMode;
use Cbox\Id\Directory\Models\Directory;

/**
 * Decides how far a directory's deprovisioning reaches: the whole account, or only the
 * membership of the organization the directory belongs to.
 *
 * A contract so a host can decide per directory or per organization; the default reads
 * the directory's environment (see {@see DeprovisioningMode}).
 */
interface DeprovisioningPolicy
{
    public function modeFor(Directory $directory): DeprovisioningMode;
}
