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
            'token_endpoint_auth_method' => self::authMethod($client),
            'grant_types' => array_values($client->grant_types),
            'response_types' => in_array('authorization_code', $client->grant_types, true) ? ['code'] : [],
            'redirect_uris' => array_values($client->redirect_uris),
            'scope' => implode(' ', $client->scopes),
            // Echoed so the registrant can read back what the server actually stored —
            // RFC 7591 §3.2.1 says the response states the registered metadata, and a
            // client rotating keys through RFC 7592 has no other way to confirm which
            // set is live. Public halves only; the private key never came here.
            ...($client->jwks !== null ? ['jwks' => $client->jwks] : []),
        ];
    }

    /**
     * What this client actually authenticates with.
     *
     * DERIVED FROM ITS CREDENTIAL, not from its type. This returned
     * `client_secret_basic` for every confidential client, which is wrong for the one kind
     * that holds no secret: a `private_key_jwt` client registers a JWK Set and the registry
     * deliberately issues it no secret. The document therefore told such a client to
     * authenticate with a Basic header it had no password for — in the same response that
     * was supposed to complete its registration.
     */
    private static function authMethod(Client $client): string
    {
        // WHAT THE CLIENT REGISTERED, when we know it. Inference is right about what a
        // client CAN do and wrong about what it asked for: the two shared-secret methods
        // look identical in the row, so a client that registered `client_secret_post` was
        // handed a document telling it to use Basic.
        if ($client->token_endpoint_auth_method !== null) {
            return $client->token_endpoint_auth_method->value;
        }

        // A row from before the column existed, or one written by a caller that did not
        // set it. The old inference, unchanged, so nothing that works today stops.
        if ($client->type === ClientType::Public) {
            return 'none';
        }

        return $client->jwks !== null ? 'private_key_jwt' : 'client_secret_basic';
    }
}
