<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Platform\Contracts\ManagementScopes;
use Cbox\Id\Platform\Enums\EnvironmentApiScope;

/**
 * The default {@see ManagementScopes}: exactly the {@see EnvironmentApiScope} enum.
 */
class EnumManagementScopes implements ManagementScopes
{
    public function knows(string $scope): bool
    {
        return EnvironmentApiScope::tryFrom($scope) !== null;
    }

    public function all(): array
    {
        return EnvironmentApiScope::all();
    }

    public function offerable(): array
    {
        return EnvironmentApiScope::offerableValues();
    }
}
