<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Testing;

use Cbox\Id\AccessControl\Contracts\Roles;

trait InteractsWithAccessControl
{
    /**
     * Define a role with permissions and assign it to a user in one step.
     *
     * @param  list<string>  $permissions
     */
    protected function grantRole(string $userId, string $organizationId, string $roleName, array $permissions): void
    {
        $roles = app(Roles::class);
        $role = $roles->define($organizationId, $roleName);

        foreach ($permissions as $permission) {
            $roles->grantPermission($organizationId, $role->id, $permission);
        }

        $roles->assign($organizationId, $userId, $role->id);
    }
}
