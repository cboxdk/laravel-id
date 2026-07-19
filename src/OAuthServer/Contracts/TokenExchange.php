<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Exceptions\InvalidTokenExchange;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\IssuedToken;
use Cbox\Id\OAuthServer\ValueObjects\TokenExchangeRequest;

/**
 * RFC 8693 OAuth 2.0 Token Exchange. Exchanges a valid subject token for a new access
 * token — narrowed in scope and/or re-bound to a target resource (audience) — for the
 * same subject. Used for cross-audience token brokering and down-scoping to a
 * downstream service (a common CDP / service-mesh need).
 */
interface TokenExchange
{
    /**
     * @throws InvalidTokenExchange when the subject token is inactive/unknown, the
     *                              token type is unsupported, or the requested scope
     *                              exceeds the subject token's scope.
     */
    public function exchange(Client $client, TokenExchangeRequest $request): IssuedToken;
}
