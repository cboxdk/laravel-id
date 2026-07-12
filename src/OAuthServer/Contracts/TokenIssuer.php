<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\IssuedToken;

interface TokenIssuer
{
    /**
     * client_credentials grant: a token for the client itself (M2M).
     *
     * @param  list<string>  $scopes  requested scopes (narrowed to the client's grants)
     * @param  string|null  $resource  RFC 8707 resource indicator; binds the token's
     *                                 `aud` to a specific resource server
     */
    public function issueClientCredentials(Client $client, array $scopes = [], ?string $resource = null): IssuedToken;

    /**
     * A token for a user in the context of a client (e.g. after an SSO login).
     *
     * @param  list<string>  $scopes
     * @param  string|null  $resource  RFC 8707 resource indicator (see above)
     */
    public function issueForUser(Client $client, string $userId, ?string $organizationId, array $scopes = [], ?string $resource = null): IssuedToken;
}
