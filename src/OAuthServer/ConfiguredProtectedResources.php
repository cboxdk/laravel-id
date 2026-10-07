<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\ProtectedResources;
use Cbox\Id\OAuthServer\Enums\ProtocolScope;
use Cbox\Id\OAuthServer\Exceptions\InvalidProtectedResource;
use Cbox\Id\OAuthServer\ValueObjects\ProtectedResource;

/**
 * The default {@see ProtectedResources}: the resources listed in
 * `cbox-id.oauth.protected_resources`.
 *
 * Each entry names its identifier either absolutely (`identifier`) or as a `path` joined
 * to the environment's issuer. The path form is the one a multi-tenant host wants: every
 * environment serves the same endpoint on its own host, so `['path' => '/mcp']` is
 * `https://acme.example/mcp` for one tenant and `https://globex.example/mcp` for the next,
 * from one line of config — the same reasoning as `authorization_endpoint_path`.
 *
 * Read per call, never cached on the instance: the binding is a singleton and the issuer
 * differs per environment.
 */
class ConfiguredProtectedResources implements ProtectedResources
{
    public function __construct(private readonly IssuerResolver $issuers) {}

    public function all(): array
    {
        $configured = config('cbox-id.oauth.protected_resources', []);

        if (! is_array($configured)) {
            return [];
        }

        $resources = [];

        foreach ($configured as $entry) {
            if (is_array($entry)) {
                $resources[] = $this->fromConfig($entry);
            }
        }

        return $resources;
    }

    public function find(string $identifier): ?ProtectedResource
    {
        foreach ($this->all() as $resource) {
            if ($resource->identifier === $identifier) {
                return $resource;
            }
        }

        return null;
    }

    public function forMetadataPath(string $path): ?ProtectedResource
    {
        $path = '/'.trim($path, '/');

        foreach ($this->all() as $resource) {
            if ($resource->metadataPath() === $path) {
                return $resource;
            }
        }

        return null;
    }

    /**
     * The protocol scopes, in the order discovery has always listed them. A host whose
     * own UserInfo-adjacent endpoints accept more rebinds the contract.
     */
    public function issuerScopes(): array
    {
        return ProtocolScope::values();
    }

    /**
     * @param  array<array-key, mixed>  $entry
     */
    private function fromConfig(array $entry): ProtectedResource
    {
        return new ProtectedResource(
            identifier: $this->identifier($entry),
            scopes: $this->strings($entry['scopes'] ?? []),
            dynamicClients: filter_var($entry['dynamic_clients'] ?? false, FILTER_VALIDATE_BOOL),
            name: $this->optional($entry['name'] ?? null),
            documentation: $this->optional($entry['documentation'] ?? null),
            clientId: $this->optional($entry['client_id'] ?? null),
        );
    }

    /**
     * @param  array<array-key, mixed>  $entry
     */
    private function identifier(array $entry): string
    {
        $identifier = $entry['identifier'] ?? null;

        if (is_string($identifier) && $identifier !== '') {
            return $identifier;
        }

        $path = $entry['path'] ?? null;

        if (is_string($path) && trim($path, '/') !== '') {
            return rtrim($this->issuers->issuer(), '/').'/'.trim($path, '/');
        }

        throw InvalidProtectedResource::missingIdentifier();
    }

    /**
     * @return list<string>
     */
    private function strings(mixed $value): array
    {
        if (is_string($value)) {
            $value = explode(' ', $value);
        }

        if (! is_array($value)) {
            return [];
        }

        return array_values(array_unique(array_filter($value, static fn (mixed $scope): bool => is_string($scope) && $scope !== '')));
    }

    private function optional(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
