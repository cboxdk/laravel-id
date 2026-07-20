<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\TokenExchange;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Exceptions\InvalidTokenExchange;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\Introspection;
use Cbox\Id\OAuthServer\ValueObjects\TokenExchangeRequest;
use Cbox\Id\OAuthServer\ValueObjects\TokenExchangeResult;

/**
 * RFC 8693 token exchange. Deny-by-default: the subject token must be active and
 * issued by us (verified via {@see TokenIntrospector}), the requested scope must be a
 * SUBSET of the subject token's (down-scope only — an exchange can never widen scope),
 * and the resulting token can be re-bound to a target resource/audience. The new token
 * is issued for the same subject and inherits its organization.
 */
class TokenExchangeService implements TokenExchange
{
    public function __construct(
        private readonly TokenIntrospector $introspector,
        private readonly TokenIssuer $issuer,
    ) {}

    public function exchange(Client $client, TokenExchangeRequest $request): TokenExchangeResult
    {
        if ($request->subjectTokenType !== TokenExchangeRequest::ACCESS_TOKEN_TYPE) {
            throw InvalidTokenExchange::unsupportedTokenType($request->subjectTokenType);
        }

        // We only ever mint an access token; a client that explicitly asks for another
        // issued type gets a clear error instead of a silently-wrong token.
        if ($request->requestedTokenType !== null
            && $request->requestedTokenType !== TokenExchangeRequest::ACCESS_TOKEN_TYPE) {
            throw InvalidTokenExchange::unsupportedRequestedType($request->requestedTokenType);
        }

        $resource = $this->validatedResource($request->resource);

        $subject = $this->introspector->introspect($request->subjectToken);

        if (! $subject->active || $subject->subject === null) {
            throw InvalidTokenExchange::inactiveSubject();
        }

        // The subject token must have been meant for THIS client — issued to it
        // (client_id) or naming it in its audience. Otherwise any client that got hold
        // of an unrelated user's token could launder it into a token of its own. Full
        // cross-client delegation (RFC 8693 actor_token / may_act) is not offered.
        if (! $this->intendedFor($client, $subject)) {
            throw InvalidTokenExchange::unauthorizedClient();
        }

        // Down-scope only: every requested scope must already be present on the
        // subject token. An empty request keeps the subject token's scopes.
        $scopes = $request->requestedScopes === [] ? $subject->scopes : $request->requestedScopes;

        foreach ($scopes as $scope) {
            if (! $subject->hasScope($scope)) {
                throw InvalidTokenExchange::scopeExceeded();
            }
        }

        $org = $subject->claims['org'] ?? null;

        $issued = $this->issuer->issueForUser(
            $client,
            $subject->subject,
            is_string($org) && $org !== '' ? $org : null,
            $scopes,
            $resource,
            $request->dpopJkt,
        );

        return new TokenExchangeResult($issued, $scopes);
    }

    /**
     * A `resource` (RFC 8707) rebinds the new token's audience, so it must be a
     * well-formed ABSOLUTE URI — never a relative path or arbitrary string that could
     * seed a misleading `aud`. Null (no rebinding) is fine.
     */
    private function validatedResource(?string $resource): ?string
    {
        if ($resource === null) {
            return null;
        }

        $scheme = parse_url($resource, PHP_URL_SCHEME);

        if (! is_string($scheme) || $scheme === '' || filter_var($resource, FILTER_VALIDATE_URL) === false) {
            throw InvalidTokenExchange::invalidResource();
        }

        return $resource;
    }

    private function intendedFor(Client $client, Introspection $subject): bool
    {
        if ($subject->clientId === $client->client_id) {
            return true;
        }

        $aud = $subject->claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];

        return in_array($client->client_id, $audiences, true);
    }
}
