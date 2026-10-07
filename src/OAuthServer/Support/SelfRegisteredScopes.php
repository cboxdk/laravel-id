<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\OAuthServer\Contracts\ProtectedResources;
use Cbox\Id\OAuthServer\Enums\ProtocolScope;

/**
 * The scopes a client that registered ITSELF for a protected resource may hold — under
 * RFC 7591 registration in `mcp` mode, and as a client ID metadata document client.
 *
 * Narrower than `open` registration on purpose. Such a client is anyone who could reach
 * the registration endpoint or host a JSON file, so it may hold exactly two kinds of scope:
 *
 *  - the scopes of host-declared resources that opted in to self-registered clients
 *    ({@see ProtectedResources}, `dynamic_clients`) — the resources it registered to use;
 *  - the protocol scopes the operator allows self-registered clients
 *    (`dynamic_registration.allowed_scopes` ∩ {@see ProtocolScope}), so it can sign the
 *    person in and keep a refresh token.
 *
 * Never a registered API's scope, never a free-text scope from the allow-list, and never a
 * reserved one ({@see ReservedScopes}), whatever any of the lists say.
 */
class SelfRegisteredScopes
{
    public function __construct(private readonly ProtectedResources $resources) {}

    /**
     * @return list<string>
     */
    public function allowed(): array
    {
        $resourceScopes = [];

        foreach ($this->resources->all() as $resource) {
            if ($resource->dynamicClients) {
                array_push($resourceScopes, ...$resource->scopes);
            }
        }

        return array_values(array_diff(
            array_unique([...$resourceScopes, ...$this->protocolScopes()]),
            ReservedScopes::all(),
        ));
    }

    /**
     * What a client that asked for nothing in particular is registered for: every scope
     * of every resource open to it, plus `offline_access` when it may refresh — an MCP
     * client registers once and asks for scopes at `/authorize`, where the registered set
     * is the ceiling.
     *
     * @return list<string>
     */
    public function defaults(bool $refreshes): array
    {
        $allowed = $this->allowed();

        return array_values(array_filter($allowed, static fn (string $scope): bool => ! ProtocolScope::isProtocol($scope)
            || ($refreshes && $scope === ProtocolScope::OfflineAccess->value)));
    }

    /**
     * The requested scopes this kind of client may hold; with nothing requested, the
     * defaults. RFC 7591 §2 lets a server narrow a request, and the registration response
     * says what was kept.
     *
     * @param  list<string>|null  $requested  null = the client named no scope at all
     * @return list<string>
     */
    public function narrow(?array $requested, bool $refreshes): array
    {
        if ($requested === null) {
            return $this->defaults($refreshes);
        }

        $allowed = $this->allowed();

        return array_values(array_unique(array_filter($requested, static fn (string $scope): bool => in_array($scope, $allowed, true))));
    }

    /**
     * @return list<string>
     */
    private function protocolScopes(): array
    {
        $configured = config('cbox-id.oauth.dynamic_registration.allowed_scopes', []);

        return is_array($configured)
            ? array_values(array_filter($configured, static fn (mixed $scope): bool => is_string($scope) && ProtocolScope::isProtocol($scope)))
            : [];
    }
}
