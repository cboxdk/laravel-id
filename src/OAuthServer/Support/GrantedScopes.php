<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\OAuthServer\Models\Client;

/**
 * What a client actually gets, as opposed to what it asked for.
 *
 * A client's registered scopes are a CEILING, and the ceiling has to be applied once — at
 * the moment the grant is created — rather than separately by everything that later reads
 * the grant. It used to be applied in exactly one place, {@see JwtTokenIssuer::grantScopes()},
 * which meant the access token was correctly downscoped and nothing else was:
 *
 *   - the device and CIBA grants stored the REQUESTED scopes verbatim;
 *   - the token endpoint read those raw scopes to decide whether to mint a refresh token,
 *     and put them on it;
 *   - so a client registered for `openid` alone could ask a device grant for
 *     `openid offline_access`, get a properly downscoped ACCESS token, and a refresh token
 *     anyway — carrying a scope its registration explicitly withheld, and rotating
 *     indefinitely.
 *
 * The fix is not another filter at the token endpoint. It is that a grant never comes into
 * existence holding scopes the client cannot have, so every reader downstream — access
 * token, id_token, refresh token, the echoed `scope` — inherits one answer instead of
 * each deriving its own.
 *
 * An empty request means "everything this client holds", which is what the authorization
 * server has always answered and what RFC 6749 §3.3 allows.
 */
final class GrantedScopes
{
    /**
     * @param  list<string>  $requested
     * @return list<string>
     */
    public static function for(Client $client, array $requested): array
    {
        if ($requested === []) {
            return array_values($client->scopes);
        }

        return array_values(array_filter(
            $requested,
            static fn (string $scope): bool => $client->allows($scope),
        ));
    }
}
