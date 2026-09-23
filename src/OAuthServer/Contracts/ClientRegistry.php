<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\OAuthServer\Exceptions\ClientSecretRefused;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ClientBlueprint;
use Cbox\Id\OAuthServer\ValueObjects\ClientSecretSummary;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Cbox\Id\OAuthServer\ValueObjects\RotatedClientSecret;

/**
 * OAuth clients (apps) in the current environment: their lifecycle, their secrets, and
 * their configuration as a portable blueprint.
 *
 * Every write is audited here — `app.created`, `app.updated`, `app.secret_rotated`,
 * `app.secret_revoked`, `app.deleted` — so every console built on this gets the trail
 * without writing it. Pass an {@see AuditActor} for who asked; without one the entry
 * names the system.
 *
 * Authorization is the caller's: these methods act on the client they are handed. Resolve
 * it through whatever scope your caller may see before calling.
 */
interface ClientRegistry
{
    /**
     * @throws InvalidClientMetadata when the settings are incoherent (an unknown grant,
     *                               token exchange on a public client, a TTL out of bounds)
     */
    public function register(NewClient $input, ?AuditActor $actor = null): RegisteredClient;

    /**
     * Replace the client's settings with the blueprint's. The client type and the
     * authentication method cannot change here — they decide what credential the client
     * holds; register a new client instead. Records `app.updated` only when something
     * actually changed.
     *
     * @throws InvalidClientMetadata
     */
    public function update(Client $client, ClientBlueprint $settings, ?AuditActor $actor = null): Client;

    /** Delete the client and every secret it holds. */
    public function delete(Client $client, ?AuditActor $actor = null): void;

    public function byClientId(string $clientId): ?Client;

    /**
     * Whether the presented secret matches any live secret of the client, compared in
     * constant time. A secret past its `expires_at` never matches.
     */
    public function verifySecret(Client $client, string $secret): bool;

    /** Whether the client holds at least one live secret. */
    public function hasSecret(Client $client): bool;

    /**
     * The client's live secrets, newest first — ids, hints and dates, never the secrets.
     *
     * @return list<ClientSecretSummary>
     */
    public function secrets(Client $client): array;

    /**
     * Mint a new secret and retire the current ones after `$graceSeconds` — the overlap in
     * which deployments move to the new secret. 0 retires them immediately. A rotation
     * never extends a secret already due to expire sooner.
     *
     * @throws ClientSecretRefused for a public or `private_key_jwt` client, or a grace
     *                             period outside [0, `cbox-id.oauth.client_secrets.max_rotation_grace`]
     */
    public function rotateSecret(Client $client, int $graceSeconds = 0, ?AuditActor $actor = null): RotatedClientSecret;

    /**
     * Revoke one live secret now. Refused for the last live secret of a client that
     * authenticates with one — rotate instead, or delete the client.
     *
     * @throws ClientSecretRefused
     */
    public function revokeSecret(Client $client, string $secretId, ?AuditActor $actor = null): void;

    /** The client's configuration, without its identity or credentials. */
    public function blueprint(Client $client): ClientBlueprint;

    /**
     * Create a NEW client in the current environment from a blueprint — a fresh
     * `client_id` and, for a shared-secret client, a fresh secret (returned once).
     * A `private_key_jwt` blueprint needs the target environment's `$jwks`.
     *
     * @param  array<string, mixed>|null  $jwks
     *
     * @throws InvalidClientMetadata
     */
    public function import(ClientBlueprint $blueprint, ?string $organizationId = null, ?array $jwks = null, ?AuditActor $actor = null): RegisteredClient;
}
