<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Exceptions;

use Cbox\Id\AccessControl\Contracts\GrantGuard;
use RuntimeException;

/**
 * A role assignment a {@see GrantGuard} vetoed.
 *
 * Thrown rather than returned so no caller can ignore it by forgetting to check a return
 * value — which is how the check came to be missing on the directory path in the first
 * place. Callers that grant in BULK (a directory reconcile walking a group's members)
 * should catch it per user, audit the refusal and carry on: one person's conflicting
 * mapping must not abandon everyone else's sync.
 */
class GrantRefused extends RuntimeException
{
    public function __construct(
        public readonly string $organizationId,
        public readonly string $userId,
        public readonly string $roleId,
        string $reason,
    ) {
        parent::__construct($reason);
    }
}
