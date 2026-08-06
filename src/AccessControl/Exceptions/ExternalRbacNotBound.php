<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Exceptions;

use RuntimeException;

/**
 * Thrown when the platform runs with `access_control.driver = 'external'` but the
 * host has not bound its own RBAC implementation for the contract being called.
 *
 * The read path (AccessChecker) deny-by-defaults silently — an unbound backend
 * simply grants nothing. The write/sync paths (Roles, GroupRoleMappings) instead
 * fail loud here, so a SCIM group→role sync or a governance revoke can never be
 * quietly dropped against a backend that was never wired.
 */
class ExternalRbacNotBound extends RuntimeException
{
    public static function forContract(string $contract): self
    {
        return new self(
            "cbox-id access_control.driver is 'external' but no {$contract} implementation is bound. "
            .'Bind your own adapter in a service provider (see docs/extension-points/custom-rbac.md).'
        );
    }
}
