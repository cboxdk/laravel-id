<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Testing;

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\ServiceAccounts;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;

trait InteractsWithOAuth
{
    /**
     * @param  list<string>  $scopes
     */
    protected function makeServiceAccount(string $organizationId, array $scopes = ['api.read'], string $name = 'CI bot'): RegisteredClient
    {
        return app(ServiceAccounts::class)->create($organizationId, $name, $scopes);
    }

    /**
     * @param  list<string>  $scopes
     */
    protected function makeClient(array $scopes = ['api.read'], ClientType $type = ClientType::Confidential): RegisteredClient
    {
        return app(ClientRegistry::class)->register(new NewClient('Test client', $type, scopes: $scopes));
    }
}
