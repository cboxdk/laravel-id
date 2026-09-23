<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Exceptions;

/**
 * A tenant-plane grant named a role no tenant may hand out: a staff-only role
 * (`tenant_assignable` false), an orphaned one, or one outside the organization.
 *
 * A subclass of {@see UnknownRole} on purpose. Every surface that already maps an
 * unknown role to "not found" keeps doing so, which is also the right answer to a
 * tenant administrator: a staff role is not theirs to grant, and a response that
 * distinguished "exists but is staff-only" from "does not exist" would let them probe
 * the vendor's role catalog one id at a time. The distinct class and message are for
 * the logs and the tests, which must be able to tell this refusal from any other.
 */
class RoleNotTenantAssignable extends UnknownRole
{
    public static function forRole(string $roleId): self
    {
        return new self("Role [{$roleId}] cannot be granted from the organization plane.");
    }
}
