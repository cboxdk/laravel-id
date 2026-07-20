<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Exceptions;

use RuntimeException;

/**
 * A privileged project operation (e.g. adding an environment) was attempted for a
 * project that is not active — its own billing/plan state has suspended it. The
 * defence-in-depth guard on the write path, alongside {@see AccountSuspended}.
 */
class ProjectSuspended extends RuntimeException
{
    public static function make(string $projectId): self
    {
        return new self("Project [{$projectId}] is not active.");
    }
}
