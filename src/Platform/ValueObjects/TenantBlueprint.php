<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\ValueObjects;

/**
 * Everything needed to stand a new customer up in one call.
 *
 * It was `AccountBlueprint` and its first field was `accountName`. The rename is not
 * cosmetic: an account was a row of its own that shadowed an organization one-to-one, and
 * naming the input after it is what made it feel like two things were being created. One
 * customer, one name.
 *
 * `environmentLimit` is the FIRST PROJECT's allowance, not the organization's. Billing
 * attaches to the product, so an organization that later buys a second product gets its
 * own allowance rather than drawing on a shared pool — which is also why there is no
 * organization-level limit for this to seed.
 */
readonly class TenantBlueprint
{
    public function __construct(
        public string $organizationName,
        public string $ownerEmail,
        public ?string $ownerName,
        public string $ownerPassword,
        public string $environmentName = 'Production',
        public ?string $domain = null,
        public int $environmentLimit = 2,
    ) {}
}
