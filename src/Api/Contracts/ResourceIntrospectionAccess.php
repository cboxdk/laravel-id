<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Contracts;

use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\Introspection;

interface ResourceIntrospectionAccess
{
    /** Whether this authenticated resource server may inspect another client's token. */
    public function allows(Client $caller, Introspection $token): bool;
}
