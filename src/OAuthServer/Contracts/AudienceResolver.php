<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ResolvedAudience;
use Cbox\Id\OAuthServer\ValueObjects\ScopeHolder;

/**
 * Decides what an access token is for — its scopes, its `aud`, and whose roles and
 * permissions it carries — from the client, the scopes it is being granted and the RFC
 * 8707 `resource` it named.
 *
 * ONE ANSWER FOR EVERY GRANT. Every access token this package mints passes through
 * {@see TokenIssuer}, and the issuer asks this once per token: authorization code,
 * refresh, client credentials, device, CIBA and token exchange cannot drift apart on who
 * a token may be audienced to, because none of them decides it.
 */
interface AudienceResolver
{
    /**
     * @param  list<string>  $scopes  what the token would carry, already capped at the client's registration
     *
     * @throws InvalidAudience when the scopes span several APIs and no resource was named, or nothing survives
     */
    public function resolve(Client $client, array $scopes, ?string $resource): ResolvedAudience;

    /**
     * The registered scopes among `$scopes` that `$holder` may not hold.
     *
     * @param  list<string>  $scopes
     * @return list<string>
     */
    public function ungrantable(ScopeHolder $holder, array $scopes): array;
}
