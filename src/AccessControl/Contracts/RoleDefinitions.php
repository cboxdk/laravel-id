<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\AccessControl\Manifest\DeclaredRole;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;

interface RoleDefinitions
{
    public function stage(Role $role, DeclaredRole $definition): void;

    /** The caller authorizes environment-level definition management before activation. */
    public function activate(string $roleId, string $expectedVersion, AuditActor $actor): Role;
}
