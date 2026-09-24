<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\ValueObjects;

/** The answer for one permission key within a {@see PermissionDecision}. */
readonly class PermissionCheck
{
    public function __construct(
        public string $permission,
        public bool $allowed,
    ) {}
}
