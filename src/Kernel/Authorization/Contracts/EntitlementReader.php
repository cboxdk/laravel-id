<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Contracts;

use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;

interface EntitlementReader
{
    /**
     * The org's current value for a key, or null if unset/expired.
     */
    public function get(string $organizationId, string $key): ?EntitlementValue;

    /**
     * All current (non-expired) entitlements for the org, keyed by entitlement key.
     *
     * @return array<string, EntitlementValue>
     */
    public function all(string $organizationId): array;
}
