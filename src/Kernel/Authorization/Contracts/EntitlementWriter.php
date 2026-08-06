<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Contracts;

use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;

/**
 * The push side of the entitlement projection — fed from billing (Cashier) or apps.
 * Central ID is not the source of truth; every write records its source and version,
 * appends to history, emits an event, and writes an audit entry.
 */
interface EntitlementWriter
{
    public function set(
        string $organizationId,
        EntitlementInput $input,
        EntitlementSource $source,
        ?string $sourceRef = null,
    ): EntitlementValue;

    public function revoke(string $organizationId, string $key, EntitlementSource $source): void;

    /**
     * Reconcile the org's entitlements against the authoritative external state:
     * upsert everything present, revoke anything absent. Guards against drift from
     * lost pushes.
     *
     * @param  list<EntitlementInput>  $authoritative
     */
    public function reconcile(string $organizationId, array $authoritative, EntitlementSource $source): void;
}
