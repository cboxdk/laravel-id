<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\TokenScope;
use RuntimeException;

/**
 * A token must never out-rank the member minting it — enforced in the issuing
 * service so no HTTP layer can forget the check.
 */
class TokenScopeExceedsIssuerRole extends RuntimeException
{
    public static function make(string $organizationId, TokenScope $scope, ?MembershipRole $role): self
    {
        $held = $role === null ? 'none' : $role->value;

        return new self(
            "Scope [{$scope->value}] exceeds the issuer's effective role [{$held}] in organization [{$organizationId}].",
        );
    }
}
