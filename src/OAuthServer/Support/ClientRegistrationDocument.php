<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\Client;

/**
 * Builds the RFC 7591 §3.2.1 / RFC 7592 client information response for a client.
 * Secrets (client_secret, registration_access_token) are added by the caller and
 * only on creation — this document is safe to return on every read.
 */
class ClientRegistrationDocument
{
    /**
     * @return array<string, mixed>
     */
    public static function for(Client $client): array
    {
        return [
            'client_id' => $client->client_id,
            'client_id_issued_at' => $client->created_at?->getTimestamp(),
            'client_name' => $client->name,
            'token_endpoint_auth_method' => $client->type === ClientType::Public ? 'none' : 'client_secret_basic',
            'grant_types' => array_values($client->grant_types),
            'response_types' => in_array('authorization_code', $client->grant_types, true) ? ['code'] : [],
            'redirect_uris' => array_values($client->redirect_uris),
            'scope' => implode(' ', $client->scopes),
        ];
    }
}
