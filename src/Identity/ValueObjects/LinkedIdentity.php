<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Contracts\Subjects;

/**
 * A federated identity linked to a local subject — the "connected accounts" view:
 * the external provider and the subject identifier it asserted. A typed value object
 * rather than an `array{provider, subject}` shape so the connected-identities surface
 * has a real, discoverable type across the {@see Subjects}
 * contract, mirroring {@see FederatedPrincipal} for the inbound direction.
 */
final readonly class LinkedIdentity
{
    public function __construct(
        public string $provider,
        public string $subject,
    ) {}
}
