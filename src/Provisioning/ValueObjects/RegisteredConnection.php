<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\ValueObjects;

use Cbox\Id\Provisioning\Models\ProvisioningConnection;

/**
 * Returned from registration. Unlike a webhook endpoint (whose signing secret the
 * platform GENERATES and reveals once), a provisioning connection's secret is
 * supplied BY the operator (the downstream app's token), so there is nothing to
 * reveal back — it is sealed on the way in and never exposed again. This wrapper
 * exists to keep a symmetric, explicit registration return type.
 */
final readonly class RegisteredConnection
{
    public function __construct(
        public ProvisioningConnection $connection,
    ) {}
}
