<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Exceptions;

use Cbox\Id\Platform\Models\Project;
use RuntimeException;

/**
 * The project has already provisioned as many environments as its plan allows
 * ({@see Project::$environment_limit}). Raising the limit is a billing/plan change
 * (billing lives on the project), not something the provisioning path decides — so
 * it is refused here rather than silently exceeded.
 */
final class EnvironmentLimitReached extends RuntimeException
{
    public static function make(string $projectId, int $limit): self
    {
        return new self("Project [{$projectId}] has reached its plan limit of {$limit} environment(s).");
    }
}
