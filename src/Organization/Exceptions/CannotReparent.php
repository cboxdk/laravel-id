<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use RuntimeException;

/**
 * Guards the closure tree against cycles: an organization can never be moved
 * beneath itself or beneath one of its own descendants (that would loop the
 * management tree).
 */
class CannotReparent extends RuntimeException
{
    public static function intoOwnSubtree(string $organizationId, string $parentId): self
    {
        return new self("Organization [{$organizationId}] cannot be moved under [{$parentId}]: it is within its own subtree.");
    }
}
