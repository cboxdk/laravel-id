<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing;

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;

/**
 * Overlays an on-prem license's deployment-wide grants on top of the org-scoped
 * entitlement reader. A license covers the whole install, so its grants apply to
 * every org and take precedence over the projected (billing/manual) values.
 *
 * With no license the grant set is empty and this is a transparent pass-through,
 * so it can wrap the reader unconditionally (deny-by-default: unlicensed = base
 * entitlements only). It decorates only the read side; the writer is untouched.
 */
final class LicenseAwareEntitlements implements EntitlementReader
{
    /**
     * @param  array<string, EntitlementValue>  $grants  license grants, keyed by entitlement key
     */
    public function __construct(
        private readonly EntitlementReader $base,
        private readonly array $grants,
    ) {}

    public function get(string $organizationId, string $key): ?EntitlementValue
    {
        return $this->grants[$key] ?? $this->base->get($organizationId, $key);
    }

    public function all(string $organizationId): array
    {
        return array_merge($this->base->all($organizationId), $this->grants);
    }
}
