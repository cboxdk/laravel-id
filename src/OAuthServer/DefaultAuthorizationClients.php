<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\AuthorizationClients;
use Cbox\Id\OAuthServer\Contracts\ClientIdMetadataDocuments;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizationClient;

/**
 * The default {@see AuthorizationClients}: the registry first, then — only for an id the
 * registry does not know — a client ID metadata document.
 *
 * Registered first, always. A registered client whose id happens to be a URL is that
 * registration, never a document someone else published at the same address.
 */
class DefaultAuthorizationClients implements AuthorizationClients
{
    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly ClientIdMetadataDocuments $documents,
    ) {}

    public function resolve(string $clientId): ?AuthorizationClient
    {
        if ($clientId === '') {
            return null;
        }

        $registered = $this->clients->byClientId($clientId);

        if ($registered !== null) {
            return AuthorizationClient::registered($registered);
        }

        if (! $this->documents->supports($clientId)) {
            return null;
        }

        $client = $this->documents->resolve($clientId);

        return AuthorizationClient::described($client, $client->clientUri(), $client->logoUri());
    }
}
