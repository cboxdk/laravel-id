<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Exceptions;

use RuntimeException;

/**
 * A privileged provisioning operation was attempted for an organization that is not
 * active. The customer's own auth surfaces already refuse it; this is the
 * defence-in-depth guard on the write path itself.
 *
 * It was `AccountSuspended`, and for a while it was nothing at all: the account plane's
 * provisioner locked the account and refused, and when ownership moved onto the
 * organization the refusal did not move with it. A suspended customer could still be sold
 * new products and given new routable environments — they would not SERVE, because the
 * resolver gates on the owner's status, but they were created, they took slugs, and they
 * were billable. Suspension is the platform's off-switch for a delinquent or abusive
 * tenant, and an off-switch that only stops reads is not one.
 */
class OrganizationSuspended extends RuntimeException
{
    public static function make(string $organizationId): self
    {
        return new self("Organization [{$organizationId}] is not active.");
    }
}
