<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Testing;

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;

/**
 * Convenience for seeding entitlements in tests:
 *
 *     $this->grantEntitlement('org_a', 'feature.sso');
 *     $this->grantEntitlement('org_a', 'seats', ['limit' => 50]);
 */
trait InteractsWithEntitlements
{
    /**
     * @param  array<string, mixed>  $value
     */
    protected function grantEntitlement(
        string $organizationId,
        string $key,
        array $value = ['enabled' => true],
        EnforcementMode $mode = EnforcementMode::Claims,
    ): EntitlementValue {
        return app(EntitlementWriter::class)->set(
            $organizationId,
            new EntitlementInput($key, $value, $mode),
            EntitlementSource::Manual,
        );
    }
}
