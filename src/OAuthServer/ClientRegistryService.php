<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Tenancy\Support\OwnerEnvironment;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Support\BackchannelLogoutUri;
use Cbox\Id\OAuthServer\ValueObjects\ClientSecret;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Illuminate\Support\Str;

class ClientRegistryService implements ClientRegistry
{
    public function register(NewClient $input): RegisteredClient
    {
        // The named owner must live in THIS environment. `EnvironmentScope` stamps the new
        // row with the ambient one and never looks at the `organization_id` beside it, so
        // a client could be registered here claiming a tenant of somewhere else — and
        // `client_credentials` would then mint this environment's `iss` carrying that
        // environment's `org`.
        OwnerEnvironment::assertLocal($input->organizationId, Client::class);

        if ($input->backchannelLogoutUri !== null) {
            BackchannelLogoutUri::assertValid($input->backchannelLogoutUri);
        }

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
            'access_token_ttl' => $input->accessTokenTtl,
            'first_party' => $input->firstParty,
            'backchannel_logout_uri' => $input->backchannelLogoutUri,
            'backchannel_logout_session_required' => $input->backchannelLogoutSessionRequired,
        ]);

        $client->jwks = $input->jwks;

        // A confidential client authenticates EITHER by a shared secret OR by
        // signing assertions with its registered keys (`private_key_jwt`). When it
        // registers a JWK Set it gets no secret — one credential mechanism, not two.
        if ($input->type === ClientType::Confidential && $input->jwks === null) {
            $minted = ClientSecret::mint();
            $secret = $minted->plaintext;
            $client->secret_hash = $minted->hash;
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
            && hash_equals($client->secret_hash, ClientSecret::hash($secret));
    }

    public function configureBackchannelLogout(Client $client, ?string $uri, bool $sessionRequired = false): Client
    {
        // An empty string is "no URI", as a cleared console field sends it — not a
        // relative URI to refuse.
        $uri = $uri !== null && trim($uri) !== '' ? trim($uri) : null;

        if ($uri !== null) {
            BackchannelLogoutUri::assertValid($uri);
        }

        $client->forceFill([
            'backchannel_logout_uri' => $uri,
            // Meaningless without a URI; stored false so a later URI does not inherit a
            // requirement nobody set alongside it.
            'backchannel_logout_session_required' => $uri !== null && $sessionRequired,
        ])->save();

        return $client;
    }
}
