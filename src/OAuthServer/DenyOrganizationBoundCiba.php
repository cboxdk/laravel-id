<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\CibaOrganizationPolicy;
use Cbox\Id\OAuthServer\Models\Client;

class DenyOrganizationBoundCiba implements CibaOrganizationPolicy
{
    public function allows(Client $client, string $organizationId, string $resource): bool
    {
        return false;
    }
}
