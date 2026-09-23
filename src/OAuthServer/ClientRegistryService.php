<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Carbon\CarbonImmutable;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Kernel\Tenancy\Support\OwnerEnvironment;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\TokenEndpointAuthMethod;
use Cbox\Id\OAuthServer\Exceptions\ClientSecretRefused;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\StoredClientSecret;
use Cbox\Id\OAuthServer\Support\AccessTokenLifetime;
use Cbox\Id\OAuthServer\Support\ClientAudit;
use Cbox\Id\OAuthServer\Support\ClientSecretStore;
use Cbox\Id\OAuthServer\Support\ClientSettingsRules;
use Cbox\Id\OAuthServer\ValueObjects\ClientBlueprint;
use Cbox\Id\OAuthServer\ValueObjects\ClientSecretSummary;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Cbox\Id\OAuthServer\ValueObjects\RotatedClientSecret;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class ClientRegistryService implements ClientRegistry
{
    /** The rotation grace ceiling when none is configured: 30 days. */
    private const DEFAULT_MAX_ROTATION_GRACE = 2_592_000;

    public function __construct(
        private readonly ClientSecretStore $secrets,
        private readonly ClientAudit $audit,
    ) {}

    public function register(NewClient $input, ?AuditActor $actor = null): RegisteredClient
    {
        return $this->create($input, $actor, []);
    }

    public function update(Client $client, ClientBlueprint $settings, ?AuditActor $actor = null): Client
    {
        // The two settings that decide what CREDENTIAL a client holds. Changing either is
        // not an edit: confidential → public would leave a live secret on a client that no
        // longer proves anything with it, and the reverse a client with no credential at
        // all. RFC 7592 self-management handles that transition, minting and clearing
        // secrets as it goes; an administrator registers a new client.
        if ($settings->type !== $client->type) {
            throw InvalidClientMetadata::metadata('client_type cannot be changed on an existing client; register a new one');
        }

        if ($settings->tokenEndpointAuthMethod !== $client->token_endpoint_auth_method) {
            throw InvalidClientMetadata::metadata('token_endpoint_auth_method cannot be changed here; register a new client');
        }

        $settings->assertValid();

        $before = ClientBlueprint::fromClient($client)->toArray();
        $after = $settings->toArray();

        $changes = [];

        foreach ($after as $key => $value) {
            if ($before[$key] !== $value) {
                $changes[$key] = ['from' => $before[$key], 'to' => $value];
            }
        }

        if ($changes === []) {
            return $client;
        }

        return DB::transaction(function () use ($client, $settings, $changes, $actor): Client {
            $client->forceFill([
                'name' => $settings->name,
                'grant_types' => $settings->grantTypes,
                'redirect_uris' => $settings->redirectUris,
                'post_logout_redirect_uris' => $settings->postLogoutRedirectUris,
                'scopes' => $settings->scopes,
                'first_party' => $settings->firstParty,
                'manifest_url' => $settings->manifestUrl,
                'access_token_ttl' => $settings->accessTokenTtl,
            ])->save();

            $this->audit->record(ClientAudit::UPDATED, $client, $actor, ['changes' => $changes]);

            return $client;
        });
    }

    public function delete(Client $client, ?AuditActor $actor = null): void
    {
        DB::transaction(function () use ($client, $actor): void {
            // The secrets go with it — by the foreign key's cascade, and by the model's
            // own `deleted` hook on an engine that does not enforce one.
            $client->delete();

            $this->audit->record(ClientAudit::DELETED, $client, $actor);
        });
    }

    public function byClientId(string $clientId): ?Client
    {
        return Client::query()->where('client_id', $clientId)->first();
    }

    public function verifySecret(Client $client, string $secret): bool
    {
        return $this->secrets->verify($client, $secret);
    }

    public function hasSecret(Client $client): bool
    {
        return $this->secrets->hasLive($client);
    }

    public function secrets(Client $client): array
    {
        return array_values($this->secrets->live($client)
            ->map(fn (StoredClientSecret $secret): ClientSecretSummary => ClientSecretSummary::of($secret))
            ->all());
    }

    public function rotateSecret(Client $client, int $graceSeconds = 0, ?AuditActor $actor = null): RotatedClientSecret
    {
        $this->assertHoldsSharedSecret($client);

        $max = $this->maxRotationGrace();

        if ($graceSeconds < 0 || $graceSeconds > $max) {
            throw ClientSecretRefused::graceOutOfRange($graceSeconds, $max);
        }

        return DB::transaction(function () use ($client, $graceSeconds, $actor): RotatedClientSecret {
            // Serialize rotations of ONE client. Two concurrent rotations would each retire
            // the other's new secret, and once the grace period ran out the client would
            // hold none at all.
            $this->lock($client);

            $hadSecrets = $this->secrets->hasLive($client);
            $issued = $this->secrets->issue($client);
            $retireAt = CarbonImmutable::now()->addSeconds($graceSeconds);

            $this->secrets->retireAllExcept($client, $issued->stored->id, $retireAt);

            $this->audit->record(ClientAudit::SECRET_ROTATED, $client, $actor, [
                'secret_id' => $issued->stored->id,
                'hint' => $issued->stored->hint,
                'grace_seconds' => $graceSeconds,
                'previous_expire_at' => $hadSecrets ? $retireAt->toIso8601String() : null,
            ]);

            return new RotatedClientSecret(
                secret: $issued->secret->plaintext,
                summary: ClientSecretSummary::of($issued->stored),
                previousExpireAt: $hadSecrets ? $retireAt : null,
            );
        });
    }

    public function revokeSecret(Client $client, string $secretId, ?AuditActor $actor = null): void
    {
        DB::transaction(function () use ($client, $secretId, $actor): void {
            $this->lock($client);

            $secret = $this->secrets->find($client, $secretId);

            if ($secret === null) {
                throw ClientSecretRefused::unknownSecret($client->client_id, $secretId);
            }

            // Revoking the last secret of a client that authenticates with one is not a
            // revocation, it is switching the app off with no replacement — and on a
            // console page it is one click from the one that was meant. Rotation (with
            // no grace) is the immediate replacement; deletion is the off switch.
            if ($this->usesSharedSecret($client) && $this->secrets->live($client)->count() <= 1) {
                throw ClientSecretRefused::lastLiveSecret($client->client_id);
            }

            $this->secrets->revoke($client, $secret);

            $this->audit->record(ClientAudit::SECRET_REVOKED, $client, $actor, [
                'secret_id' => $secret->id,
                'hint' => $secret->hint,
            ]);
        });
    }

    public function blueprint(Client $client): ClientBlueprint
    {
        return ClientBlueprint::fromClient($client);
    }

    public function import(ClientBlueprint $blueprint, ?string $organizationId = null, ?array $jwks = null, ?AuditActor $actor = null): RegisteredClient
    {
        $blueprint->assertValid();

        return $this->create(new NewClient(
            name: $blueprint->name,
            type: $blueprint->type,
            redirectUris: $blueprint->redirectUris,
            grantTypes: $blueprint->grantTypes,
            scopes: $blueprint->scopes,
            firstParty: $blueprint->firstParty,
            organizationId: $organizationId,
            jwks: $jwks,
            postLogoutRedirectUris: $blueprint->postLogoutRedirectUris,
            accessTokenTtl: $blueprint->accessTokenTtl,
            tokenEndpointAuthMethod: $blueprint->tokenEndpointAuthMethod,
            manifestUrl: $blueprint->manifestUrl,
        ), $actor, ['source' => 'blueprint']);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function create(NewClient $input, ?AuditActor $actor, array $context): RegisteredClient
    {
        // The named owner must live in THIS environment. `EnvironmentScope` stamps the new
        // row with the ambient one and never looks at the `organization_id` beside it, so
        // a client could be registered here claiming a tenant of somewhere else — and
        // `client_credentials` would then mint this environment's `iss` carrying that
        // environment's `org`.
        OwnerEnvironment::assertLocal($input->organizationId, Client::class);

        ClientSettingsRules::assertGrants($input->grantTypes, $input->type);
        ClientSettingsRules::assertAuthMethod($input->tokenEndpointAuthMethod, $input->type, $input->jwks);
        AccessTokenLifetime::assertAcceptable($input->accessTokenTtl);

        return DB::transaction(function () use ($input, $actor, $context): RegisteredClient {
            $client = new Client;
            $client->fill([
                'organization_id' => $input->organizationId,
                'client_id' => 'cid_'.Str::lower((string) Str::ulid()),
                'name' => $input->name,
                'type' => $input->type,
                'token_endpoint_auth_method' => $input->tokenEndpointAuthMethod,
                'redirect_uris' => $input->redirectUris,
                'post_logout_redirect_uris' => $input->postLogoutRedirectUris,
                'grant_types' => $input->grantTypes,
                'scopes' => $input->scopes,
                'manifest_url' => $input->manifestUrl,
                'access_token_ttl' => $input->accessTokenTtl,
                'first_party' => $input->firstParty,
            ]);

            $client->jwks = $input->jwks;
            $client->save();

            // A confidential client authenticates EITHER by a shared secret OR by
            // signing assertions with its registered keys (`private_key_jwt`). When it
            // registers a JWK Set it gets no secret — one credential mechanism, not two.
            $secret = $this->usesSharedSecret($client) ? $this->secrets->issue($client)->secret->plaintext : null;

            $this->audit->record(ClientAudit::CREATED, $client, $actor, $context + [
                'client_type' => $client->type->value,
                'grant_types' => $client->grant_types,
            ]);

            return new RegisteredClient($client, $secret);
        });
    }

    /**
     * @throws ClientSecretRefused
     */
    private function assertHoldsSharedSecret(Client $client): void
    {
        if ($client->type !== ClientType::Confidential) {
            throw ClientSecretRefused::publicClient($client->client_id);
        }

        // A private_key_jwt client is Confidential AND has no secret, by construction.
        // Minting one does not rotate anything; it ADDS a bearer credential to a client
        // that was asymmetric-only, and the authenticator would then accept client_id plus
        // secret whenever no assertion is presented.
        if (! $this->usesSharedSecret($client)) {
            throw ClientSecretRefused::signsAssertions($client->client_id);
        }
    }

    private function usesSharedSecret(Client $client): bool
    {
        return $client->type === ClientType::Confidential
            && $client->jwks === null
            && $client->token_endpoint_auth_method !== TokenEndpointAuthMethod::PrivateKeyJwt;
    }

    private function lock(Client $client): void
    {
        Client::query()->whereKey($client->id)->lockForUpdate()->first();
    }

    private function maxRotationGrace(): int
    {
        $max = config('cbox-id.oauth.client_secrets.max_rotation_grace', self::DEFAULT_MAX_ROTATION_GRACE);

        return is_numeric($max) && (int) $max >= 0 ? (int) $max : self::DEFAULT_MAX_ROTATION_GRACE;
    }
}
