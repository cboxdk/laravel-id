<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\Apis;
use Cbox\Id\OAuthServer\Contracts\AudienceResolver;
use Cbox\Id\OAuthServer\Enums\ProtocolScope;
use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ApiAudience;
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
 */
class RegisteredApiAudienceResolver implements AudienceResolver
{
    public function __construct(
        private readonly Apis $apis,
    ) {}

    public function resolve(Client $client, array $scopes, ?string $resource): ResolvedAudience
    {
        $holder = ScopeHolder::of($client);
        $environmentId = $holder->environmentId;

        $registered = $environmentId === null ? [] : $this->apis->registeredScopes($environmentId, $this->apiScopes($scopes));
        $named = $environmentId === null || $resource === null ? null : $this->apis->audience($environmentId, $resource);

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
        if ($holder->environmentId === null || $holder->isEnvironmentOwned()) {
            return [];
        }

        $refused = [];

        foreach ($this->apis->registeredScopes($holder->environmentId, $this->apiScopes($scopes)) as $key => $scope) {
            if (! $scope->mayBeHeldBy($holder)) {
                $refused[] = $key;
            }
        }

        return $refused;
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
