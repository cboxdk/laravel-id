<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Illuminate\Support\Str;

class ClientRegistryService implements ClientRegistry
{
    public function register(NewClient $input): RegisteredClient
    {
        $secret = null;

        $client = new Client;
        $client->fill([
            'organization_id' => $input->organizationId,
            'client_id' => 'cid_'.Str::lower((string) Str::ulid()),
            'name' => $input->name,
            'type' => $input->type,
            'redirect_uris' => $input->redirectUris,
            'post_logout_redirect_uris' => $input->postLogoutRedirectUris,
            'grant_types' => $input->grantTypes,
            'scopes' => $input->scopes,
            'first_party' => $input->firstParty,
        ]);

        $client->jwks = $input->jwks;

        // A confidential client authenticates EITHER by a shared secret OR by
        // signing assertions with its registered keys (`private_key_jwt`). When it
        // registers a JWK Set it gets no secret — one credential mechanism, not two.
        if ($input->type === ClientType::Confidential && $input->jwks === null) {
            $secret = 'csec_'.bin2hex(random_bytes(32));
            $client->secret_hash = hash('sha256', $secret);
        }

        $client->save();

        return new RegisteredClient($client, $secret);
    }

    public function byClientId(string $clientId): ?Client
    {
        return Client::query()->where('client_id', $clientId)->first();
    }

    public function verifySecret(Client $client, string $secret): bool
    {
        return $client->secret_hash !== null
            && hash_equals($client->secret_hash, hash('sha256', $secret));
    }
}
