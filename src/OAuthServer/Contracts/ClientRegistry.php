<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;

interface ClientRegistry
{
    public function register(NewClient $input): RegisteredClient;

    public function byClientId(string $clientId): ?Client;

    public function verifySecret(Client $client, string $secret): bool;
}
