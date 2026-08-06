<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ClientMetadata;
use Cbox\Id\OAuthServer\ValueObjects\DynamicRegistration;

/**
 * OAuth 2.0 Dynamic Client Registration (RFC 7591) and client management
 * (RFC 7592). Implementations own the policy: validating request metadata,
 * minting the client + its registration access token, and gating management
 * operations on that token.
 */
interface DynamicClientRegistration
{
    /**
     * Validate and normalize a raw RFC 7591 registration request.
     *
     * @param  array<string, mixed>  $request
     *
     * @throws InvalidClientMetadata
     */
    public function validate(array $request): ClientMetadata;

    /**
     * Register a client from already-validated metadata, returning it together
     * with its one-time secret and registration access token.
     */
    public function register(ClientMetadata $metadata): DynamicRegistration;

    /**
     * Resolve the client a registration access token manages, or null if the
     * token does not authenticate that client. Constant-time.
     */
    public function authenticate(string $clientId, string $registrationAccessToken): ?Client;

    /**
     * Replace a client's metadata (RFC 7592 PUT).
     */
    public function update(Client $client, ClientMetadata $metadata): Client;

    /**
     * Delete a registered client (RFC 7592 DELETE).
     */
    public function delete(Client $client): void;
}
