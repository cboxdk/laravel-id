<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use Cbox\Id\Platform\Models\Project;
use RuntimeException;

/**
 * The project has already provisioned as many environments as its plan allows
 * ({@see Project::$environment_limit}). Raising the limit is a billing/plan change
 * (billing lives on the project), not something the provisioning path decides — so
 * it is refused here rather than silently exceeded.
 */
class EnvironmentLimitReached extends RuntimeException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public static function make(string $projectId, int $limit): self
    {
        return (new self("Project [{$projectId}] has reached its plan limit of {$limit} environment(s)."))->withSourceMessage(new SourceMessage('Project [:projectId] has reached its plan limit of :limit environment(s).', ['projectId' => $projectId, 'limit' => $limit]));
    }
}
