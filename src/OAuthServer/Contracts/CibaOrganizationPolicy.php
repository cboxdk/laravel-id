<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Models\Client;

/** Host opt-in, checked at initiation, approval and redemption, in addition to membership. */
interface CibaOrganizationPolicy
{
    public function allows(Client $client, string $organizationId, string $resource): bool;
}
