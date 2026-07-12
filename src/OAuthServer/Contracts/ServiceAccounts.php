<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;

interface ServiceAccounts
{
    /**
     * Create an M2M service account (a confidential client). The secret is
     * revealed once in the returned value.
     *
     * @param  list<string>  $scopes
     */
    public function create(string $organizationId, string $name, array $scopes = []): RegisteredClient;
}
