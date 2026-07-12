<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Illuminate\Support\Str;

final class ClientRegistryService implements ClientRegistry
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
            'grant_types' => $input->grantTypes,
            'scopes' => $input->scopes,
            'first_party' => $input->firstParty,
        ]);

        if ($input->type === ClientType::Confidential) {
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
