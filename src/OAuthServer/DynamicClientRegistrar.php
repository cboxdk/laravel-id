<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\DynamicClientRegistration;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ClientMetadata;
use Cbox\Id\OAuthServer\ValueObjects\DynamicRegistration;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;

/**
 * RFC 7591 / 7592 implementation. Validation is deliberately strict and
 * secure-by-default: unknown grant types are rejected, requested scopes are
 * reduced to the configured allow-list, and redirect URIs must be well-formed
 * and non-fragment (loopback http is permitted for native/CLI clients, which is
 * exactly the MCP case).
 */
final class DynamicClientRegistrar implements DynamicClientRegistration
{
    private const AUTH_METHODS = ['none', 'client_secret_basic', 'client_secret_post'];

    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly EnvironmentContext $environment,
    ) {}

    public function validate(array $request): ClientMetadata
    {
        $authMethod = $this->authMethod($request);
        $grantTypes = $this->grantTypes($request);
        $responseTypes = $this->responseTypes($request, $grantTypes);
        $redirectUris = $this->redirectUris($request, $grantTypes);

        // A client that authenticates with a secret cannot be public, and a
        // public client cannot use client_credentials (it has no secret to prove).
        if ($authMethod === 'none' && in_array('client_credentials', $grantTypes, true)) {
            throw InvalidClientMetadata::metadata('client_credentials requires a confidential client (token_endpoint_auth_method must not be "none")');
        }

        return new ClientMetadata(
            clientName: $this->clientName($request),
            tokenEndpointAuthMethod: $authMethod,
            redirectUris: $redirectUris,
            grantTypes: $grantTypes,
            responseTypes: $responseTypes,
            scopes: $this->scopes($request),
        );
    }

    public function register(ClientMetadata $metadata): DynamicRegistration
    {
        $registered = $this->clients->register(new NewClient(
            name: $metadata->clientName,
            type: $metadata->isPublic() ? ClientType::Public : ClientType::Confidential,
            redirectUris: $metadata->redirectUris,
            grantTypes: $metadata->grantTypes,
            scopes: $metadata->scopes,
        ));

        $registrationToken = 'reg_'.bin2hex(random_bytes(32));

        $registered->client->forceFill([
            'registration_access_token_hash' => hash('sha256', $registrationToken),
        ])->save();

        return new DynamicRegistration($registered->client, $registered->secret, $registrationToken);
    }

    public function authenticate(string $clientId, string $registrationAccessToken): ?Client
    {
        $client = $this->clients->byClientId($clientId);
        $hasToken = $client !== null && $client->registration_access_token_hash !== null;

        // Compare against a fixed dummy when the client or its token hash is
        // absent, so a caller can't distinguish "no such client" from "wrong
        // token" by timing.
        $stored = $hasToken ? $client->registration_access_token_hash : hash('sha256', 'absent');
        $matches = hash_equals($stored, hash('sha256', $registrationAccessToken));

        return $matches && $hasToken ? $client : null;
    }

    public function update(Client $client, ClientMetadata $metadata): Client
    {
        $client->forceFill([
            'name' => $metadata->clientName,
            'type' => $metadata->isPublic() ? ClientType::Public : ClientType::Confidential,
            'redirect_uris' => $metadata->redirectUris,
            'grant_types' => $metadata->grantTypes,
            'scopes' => $metadata->scopes,
        ])->save();

        return $client;
    }

    public function delete(Client $client): void
    {
        $client->delete();
    }

    /**
     * @param  array<string, mixed>  $request
     */
    private function clientName(array $request): string
    {
        $name = $request['client_name'] ?? null;

        return is_string($name) && trim($name) !== '' ? trim($name) : 'Dynamic client';
    }

    /**
     * @param  array<string, mixed>  $request
     */
    private function authMethod(array $request): string
    {
        // RFC 7591 §2: the default when omitted is client_secret_basic.
        $method = $request['token_endpoint_auth_method'] ?? 'client_secret_basic';

        if (! is_string($method) || ! in_array($method, self::AUTH_METHODS, true)) {
            throw InvalidClientMetadata::metadata('unsupported token_endpoint_auth_method');
        }

        return $method;
    }

    /**
     * @param  array<string, mixed>  $request
     * @return list<string>
     */
    private function grantTypes(array $request): array
    {
        $requested = $this->stringList($request['grant_types'] ?? null);
        $requested = $requested === [] ? ['authorization_code'] : $requested;

        $allowed = $this->configList('allowed_grant_types');

        foreach ($requested as $grant) {
            if (! in_array($grant, $allowed, true)) {
                throw InvalidClientMetadata::metadata("grant_type not permitted: {$grant}");
            }
        }

        return array_values(array_unique($requested));
    }

    /**
     * @param  array<string, mixed>  $request
     * @param  list<string>  $grantTypes
     * @return list<string>
     */
    private function responseTypes(array $request, array $grantTypes): array
    {
        $requested = $this->stringList($request['response_types'] ?? null);
        $requested = $requested === [] ? [] : $requested;

        foreach ($requested as $type) {
            if ($type !== 'code') {
                throw InvalidClientMetadata::metadata("response_type not supported: {$type}");
            }
        }

        // The authorization_code grant implies the "code" response type.
        if (in_array('authorization_code', $grantTypes, true)) {
            return ['code'];
        }

        return $requested;
    }

    /**
     * @param  array<string, mixed>  $request
     * @param  list<string>  $grantTypes
     * @return list<string>
     */
    private function redirectUris(array $request, array $grantTypes): array
    {
        $uris = $this->stringList($request['redirect_uris'] ?? null);
        $needsRedirect = in_array('authorization_code', $grantTypes, true);

        if ($needsRedirect && $uris === []) {
            throw InvalidClientMetadata::redirectUri('redirect_uris is required for the authorization_code grant');
        }

        foreach ($uris as $uri) {
            $this->assertRedirectUri($uri);
        }

        return $uris;
    }

    private function assertRedirectUri(string $uri): void
    {
        $parts = parse_url($uri);

        if ($parts === false || ! isset($parts['scheme'])) {
            throw InvalidClientMetadata::redirectUri("redirect_uri is not an absolute URI: {$uri}");
        }

        // A fragment in a redirect URI is forbidden (RFC 6749 §3.1.2).
        if (isset($parts['fragment'])) {
            throw InvalidClientMetadata::redirectUri("redirect_uri must not contain a fragment: {$uri}");
        }

        $scheme = strtolower($parts['scheme']);

        // A private-use ("custom") URI scheme is allowed for native apps
        // (RFC 8252 §7.1), in both the authority form (com.example.app://cb) and
        // the canonical path form (com.example.app:/cb) — the latter has no host,
        // so it must be accepted before the http(s) host requirement below.
        if ($scheme !== 'http' && $scheme !== 'https') {
            return;
        }

        // http(s) reserved schemes must carry a host: https everywhere, plain http
        // only for loopback (native/CLI/MCP clients, RFC 8252 §7.3).
        $host = isset($parts['host']) ? strtolower($parts['host']) : null;
        $isLoopback = in_array($host, ['localhost', '127.0.0.1', '::1'], true);

        if ($scheme === 'https' && $host !== null) {
            return;
        }

        if ($scheme === 'http' && $isLoopback) {
            return;
        }

        // A sandbox environment is for development, so it accepts plain http on any
        // host (e.g. http://app.test) — never permitted in production.
        if ($scheme === 'http' && $host !== null && ($this->environment->current()?->isSandbox() ?? false)) {
            return;
        }

        throw InvalidClientMetadata::redirectUri("redirect_uri must use https (or http on loopback): {$uri}");
    }

    /**
     * @param  array<string, mixed>  $request
     * @return list<string>
     */
    private function scopes(array $request): array
    {
        $raw = $request['scope'] ?? '';
        $requested = is_string($raw)
            ? array_values(array_filter(explode(' ', $raw), static fn (string $s): bool => $s !== ''))
            : [];

        $allowed = $this->configList('allowed_scopes');

        // RFC 7591 §2: the server MAY reduce the requested scopes. Silently drop
        // any outside the allow-list rather than failing the whole registration.
        return array_values(array_filter($requested, static fn (string $s): bool => in_array($s, $allowed, true)));
    }

    /**
     * @return list<string>
     */
    private function stringList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, static fn (mixed $v): bool => is_string($v) && $v !== ''));
    }

    /**
     * @return list<string>
     */
    private function configList(string $key): array
    {
        $value = config("cbox-id.oauth.dynamic_registration.{$key}");

        return is_array($value) ? array_values(array_filter($value, 'is_string')) : [];
    }
}
