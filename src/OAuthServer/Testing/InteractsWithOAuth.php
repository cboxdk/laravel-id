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
     * Register a test client.
     *
     * `$grantTypes` is explicit because the token endpoint enforces the registered set:
     * a client may only use the grants it declared. Declaring them here keeps a test's
     * fixture honest about which flows it actually exercises.
     *
     * @param  list<string>  $scopes
     * @param  list<string>  $grantTypes
     */
    protected function makeClient(
        array $scopes = ['api.read'],
        ClientType $type = ClientType::Confidential,
        array $grantTypes = ['client_credentials'],
    ): RegisteredClient {
        return app(ClientRegistry::class)->register(
            new NewClient('Test client', $type, grantTypes: $grantTypes, scopes: $scopes),
        );
    }
}
