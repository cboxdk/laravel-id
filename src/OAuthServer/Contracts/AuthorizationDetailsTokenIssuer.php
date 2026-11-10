<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizationDetails;
use Cbox\Id\OAuthServer\ValueObjects\IssuedToken;

/**
 * A token issuer that can mint an exchanged token narrowed to RFC 9396
 * `authorization_details`, carrying the subject token's login facts forward.
 *
 * `$authTime` and `$acr` are what the SUBJECT token said (RFC 9470 §6.1), read from a
 * token this server signed: an exchange does not re-authenticate anyone, so the new token
 * may claim exactly the login the old one did and nothing newer or stronger.
 */
interface AuthorizationDetailsTokenIssuer extends TokenIssuer
{
    /** @param list<string> $scopes */
    public function issueForExchange(
        Client $client,
        string $userId,
        ?string $organizationId,
        array $scopes,
        AuthorizationDetails $details,
        ?int $authTime = null,
        ?string $acr = null,
        ?string $resource = null,
        ?string $dpopJkt = null,
    ): IssuedToken;
}
