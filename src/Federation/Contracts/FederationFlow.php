<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;

interface FederationFlow
{
    /**
     * Complete an SSO login for an already-validated principal: provision the
     * user, ensure org membership, and start a session. Throws if the connection
     * is not active.
     */
    public function completeLogin(Connection $connection, FederatedPrincipal $principal): Session;
}
