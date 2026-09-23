<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;

interface ClientRegistry
{
    public function register(NewClient $input): RegisteredClient;

    public function byClientId(string $clientId): ?Client;

    public function verifySecret(Client $client, string $secret): bool;

    /**
     * Set — or, with a null URI, clear — where this client is told that a person signed
     * out (OIDC Back-Channel Logout 1.0 §2.2). Validated exactly as at registration.
     *
     * @throws InvalidClientMetadata when the URI is not one this server will call
     */
    public function configureBackchannelLogout(Client $client, ?string $uri, bool $sessionRequired = false): Client;
}
