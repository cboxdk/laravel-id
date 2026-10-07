<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\Apis;
use Cbox\Id\OAuthServer\Contracts\AudienceResolver;
use Cbox\Id\OAuthServer\Contracts\ProtectedResources;
use Cbox\Id\OAuthServer\Enums\ProtocolScope;
use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Support\ReservedScopes;
use Cbox\Id\OAuthServer\ValueObjects\ApiAudience;
use Cbox\Id\OAuthServer\ValueObjects\ProtectedResource;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredScope;
use Cbox\Id\OAuthServer\ValueObjects\ResolvedAudience;
use Cbox\Id\OAuthServer\ValueObjects\ScopeHolder;

/**
 * The default {@see AudienceResolver}: registered APIs decide where their scopes may go.
 *
 * The rules, in the order they are applied:
 *
 *  1. NOTHING REGISTERED IS INVOLVED — no requested scope belongs to an API and the
 *     `resource` (if any) names none — so the token is exactly what it was before APIs
 *     existed: the scopes as given, `aud` = the resource or the issuer, the requesting
 *     client's roles. An environment that registers no APIs never leaves this branch.
 *  2. Registered scopes the client may not hold are dropped
 *     ({@see RegisteredScope::mayBeHeldBy()}). The client registry refuses to store them
 *     in the first place; this is the second wall, for rows written before the API was
 *     registered and for any writer that went around the registry.
 *  3. The target API is the one `resource` names, or — with no `resource` — the single
 *     API the remaining registered scopes belong to. Scopes of two APIs and no `resource`
 *     is `invalid_target`: guessing would pick an audience the client did not ask for.
 *  4. With a target, the token carries only that API's scopes plus the protocol scopes.
 *     Unregistered free-text scopes are dropped: they can never ride on a registered
 *     API's audience, which is what makes a squatted `tax:assess` worthless at the tax API.
 *     Without one, registered scopes are dropped instead — a registered scope is only ever
 *     valid at its own API.
 *  5. If the request carried scopes and none survived, the request is refused with
 *     `invalid_scope` rather than answered with an empty token.
 *
 * HOST-DECLARED RESOURCES ({@see ProtectedResources}) sit beside registered APIs:
 *
 *  6. A `resource` naming a declared resource (and no registered API — an API row wins a
 *     collision, because it is what an operator can see and change) audiences the token
 *     to it, carrying the protocol scopes plus the requested scopes it accepts. A
 *     self-registered client is refused with `invalid_target` unless the resource opted
 *     in to self-registered clients.
 *  7. With no `resource` and no registered scope in play, scopes that belong to exactly
 *     one declared resource pick it as the target — the same courtesy rule 3 extends to
 *     APIs. Scopes of two declared resources is `invalid_target`.
 *  8. A `resource` that is none of these — not an API, not declared, not the issuer — is
 *     refused for a self-registered client, always: such a client is whoever reached the
 *     registration endpoint, and an audience it may name freely is a token signed by us
 *     for any resource server that trusts this issuer. Operator-registered clients keep
 *     the RFC 8707 pass-through unless `oauth.resource_indicators.unknown_resources` is
 *     `refuse`.
 */
class RegisteredApiAudienceResolver implements AudienceResolver
{
    public function __construct(
        private readonly Apis $apis,
        private readonly ProtectedResources $resources,
        private readonly IssuerResolver $issuers,
    ) {}

    public function resolve(Client $client, array $scopes, ?string $resource): ResolvedAudience
    {
        $holder = ScopeHolder::of($client);
        $environmentId = $holder->environmentId;

        $registered = $environmentId === null ? [] : $this->apis->registeredScopes($environmentId, $this->apiScopes($scopes));
        $named = $environmentId === null || $resource === null ? null : $this->apis->audience($environmentId, $resource);

        if ($resource !== null && $named === null) {
            $declared = $this->resources->find($resource);

            if ($declared !== null) {
                return $this->forDeclared($client, $holder, $scopes, $registered, $declared);
            }

            $this->assertServed($holder, $resource);
        }

        if ($resource === null && $registered === []) {
            $declared = $this->declaredTarget($scopes);

            if ($declared !== null) {
                return $this->forDeclared($client, $holder, $scopes, $registered, $declared);
            }
        }

        if ($registered === [] && $named === null) {
            return new ResolvedAudience($scopes, $resource, $client->client_id);
        }

        $holdable = array_filter($registered, static fn (RegisteredScope $scope): bool => $scope->mayBeHeldBy($holder));
        $target = $resource !== null ? $named : $this->defaultTarget($holdable);

        $granted = array_values(array_filter($scopes, static function (string $scope) use ($registered, $holdable, $target): bool {
            if (ProtocolScope::isProtocol($scope)) {
                return true;
            }

            if (! isset($registered[$scope])) {
                return $target === null;
            }

            return $target !== null
                && isset($holdable[$scope])
                && $holdable[$scope]->api->id === $target->id;
        }));

        if ($scopes !== [] && $granted === []) {
            throw InvalidAudience::nothingGrantable();
        }

        return new ResolvedAudience(
            scopes: $granted,
            resource: $target->identifier ?? $resource,
            rbacClientId: $target->clientId ?? $client->client_id,
            api: $target,
            // UserInfo accepts a token only when the issuer is one of its audiences, so an
            // OIDC client that audiences its access token to an API keeps its login working.
            includesIssuer: $target !== null && in_array(ProtocolScope::OpenId->value, $granted, true),
        );
    }

    public function ungrantable(ScopeHolder $holder, array $scopes): array
    {
        // A self-registered client may never hold a reserved scope, however it came to ask.
        $refused = $holder->dynamicallyRegistered
            ? array_values(array_intersect($scopes, ReservedScopes::all()))
            : [];

        if ($holder->environmentId === null || $holder->isEnvironmentOwned()) {
            return $refused;
        }

        foreach ($this->apis->registeredScopes($holder->environmentId, $this->apiScopes($scopes)) as $key => $scope) {
            if (! $scope->mayBeHeldBy($holder)) {
                $refused[] = $key;
            }
        }

        return $refused;
    }

    /**
     * A token for a host-declared resource: the protocol scopes plus the requested scopes
     * the resource accepts. A registered API's scope never rides along — it is only ever
     * valid at its own API — and a self-registered client never carries a reserved scope,
     * whatever the resource says it accepts.
     *
     * @param  list<string>  $scopes
     * @param  array<string, RegisteredScope>  $registered
     *
     * @throws InvalidAudience
     */
    private function forDeclared(Client $client, ScopeHolder $holder, array $scopes, array $registered, ProtectedResource $declared): ResolvedAudience
    {
        if ($holder->dynamicallyRegistered && ! $declared->dynamicClients) {
            throw InvalidAudience::notOfferedToDynamicClients($declared->identifier);
        }

        $reserved = $holder->dynamicallyRegistered ? ReservedScopes::all() : [];

        $granted = array_values(array_filter($scopes, static fn (string $scope): bool => ProtocolScope::isProtocol($scope)
            || (! isset($registered[$scope]) && $declared->accepts($scope) && ! in_array($scope, $reserved, true))));

        if ($scopes !== [] && $granted === []) {
            throw InvalidAudience::nothingGrantable();
        }

        return new ResolvedAudience(
            scopes: $granted,
            resource: $declared->identifier,
            rbacClientId: $declared->clientId ?? $client->client_id,
            // The same rule as a registered API: an OIDC client that audiences its access
            // token to the resource keeps UserInfo working.
            includesIssuer: in_array(ProtocolScope::OpenId->value, $granted, true),
        );
    }

    /**
     * The one declared resource the requested non-protocol scopes belong to, when no
     * `resource` was named; null when none of them belongs to one.
     *
     * @param  list<string>  $scopes
     *
     * @throws InvalidAudience when they belong to more than one
     */
    private function declaredTarget(array $scopes): ?ProtectedResource
    {
        $requested = $this->apiScopes($scopes);

        if ($requested === []) {
            return null;
        }

        $candidates = [];

        foreach ($this->resources->all() as $resource) {
            foreach ($requested as $scope) {
                if ($resource->accepts($scope)) {
                    $candidates[$resource->identifier] = $resource;

                    break;
                }
            }
        }

        if (count($candidates) > 1) {
            $identifiers = array_keys($candidates);
            sort($identifiers);

            throw InvalidAudience::ambiguous($identifiers);
        }

        return $candidates === [] ? null : array_values($candidates)[0];
    }

    /**
     * A `resource` that names neither a registered API nor a declared resource. The issuer
     * itself is always served. Anything else is refused for a self-registered client, and
     * for everyone when the operator asked for strict resource indicators.
     *
     * @throws InvalidAudience
     */
    private function assertServed(ScopeHolder $holder, string $resource): void
    {
        if (rtrim($resource, '/') === rtrim($this->issuers->issuer(), '/')) {
            return;
        }

        if ($holder->dynamicallyRegistered || config('cbox-id.oauth.resource_indicators.unknown_resources', 'accept') === 'refuse') {
            throw InvalidAudience::unknownResource($resource);
        }
    }

    /**
     * The one API every holdable registered scope belongs to; null when there are none.
     *
     * @param  array<string, RegisteredScope>  $holdable
     *
     * @throws InvalidAudience when they belong to more than one
     */
    private function defaultTarget(array $holdable): ?ApiAudience
    {
        $apis = [];

        foreach ($holdable as $scope) {
            $apis[$scope->api->id] = $scope->api;
        }

        if (count($apis) > 1) {
            $identifiers = array_map(static fn (ApiAudience $api): string => $api->identifier, array_values($apis));
            sort($identifiers);

            throw InvalidAudience::ambiguous($identifiers);
        }

        return $apis === [] ? null : array_values($apis)[0];
    }

    /**
     * @param  list<string>  $scopes
     * @return list<string>
     */
    private function apiScopes(array $scopes): array
    {
        return array_values(array_filter($scopes, static fn (string $scope): bool => ! ProtocolScope::isProtocol($scope)));
    }
}
