<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\EnumManagementScopes;
use Cbox\Id\Platform\Enums\EnvironmentApiScope;

/**
 * The scopes a management key may carry — the vocabulary {@see EnvironmentApiKeys::issue()}
 * checks against, deny-by-default.
 *
 * A contract rather than the {@see EnvironmentApiScope} enum alone, because the host
 * decides what its management API can do: a host that adds endpoints adds the scopes that
 * guard them by rebinding this, without waiting for a release of this package. The bundled
 * {@see EnumManagementScopes} answers with the enum, which remains the core set.
 */
interface ManagementScopes
{
    /** Whether a key may carry this scope at all. */
    public function knows(string $scope): bool;

    /**
     * Every scope a key may carry, reserved ones included.
     *
     * @return list<string>
     */
    public function all(): array;

    /**
     * The scopes offered when minting a key: every known one that is not reserved.
     *
     * @return list<string>
     */
    public function offerable(): array;
}
