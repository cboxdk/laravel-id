<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\TokenExchange;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Exceptions\InvalidTokenExchange;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\IssuedToken;
use Cbox\Id\OAuthServer\ValueObjects\TokenExchangeRequest;

/**
 * RFC 8693 token exchange. Deny-by-default: the subject token must be active and
 * issued by us (verified via {@see TokenIntrospector}), the requested scope must be a
 * SUBSET of the subject token's (down-scope only — an exchange can never widen scope),
 * and the resulting token can be re-bound to a target resource/audience. The new token
 * is issued for the same subject and inherits its organization.
 */
final class TokenExchangeService implements TokenExchange
{
    public function __construct(
        private readonly TokenIntrospector $introspector,
        private readonly TokenIssuer $issuer,
    ) {}

    public function exchange(Client $client, TokenExchangeRequest $request): IssuedToken
    {
        if ($request->subjectTokenType !== TokenExchangeRequest::ACCESS_TOKEN_TYPE) {
            throw InvalidTokenExchange::unsupportedTokenType($request->subjectTokenType);
        }

        $subject = $this->introspector->introspect($request->subjectToken);

        if (! $subject->active || $subject->subject === null) {
            throw InvalidTokenExchange::inactiveSubject();
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

        return $this->issuer->issueForUser(
            $client,
            $subject->subject,
            is_string($org) && $org !== '' ? $org : null,
            $scopes,
            $request->resource,
            $request->dpopJkt,
        );
    }
}
