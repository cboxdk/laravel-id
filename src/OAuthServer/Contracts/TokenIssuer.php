<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ActingParty;
use Cbox\Id\OAuthServer\ValueObjects\IssuedToken;
use DateTimeInterface;

interface TokenIssuer
{
    /**
     * client_credentials grant: a token for the client itself (M2M).
     *
     * @param  list<string>  $scopes  requested scopes (narrowed to the client's grants)
     * @param  string|null  $resource  RFC 8707 resource indicator; binds the token's
     *                                 `aud` to a specific resource server
     * @param  string|null  $dpopJkt  RFC 9449 JWK thumbprint; sender-constrains the
     *                                token via `cnf.jkt` and marks it token_type DPoP
     */
    public function issueClientCredentials(Client $client, array $scopes = [], ?string $resource = null, ?string $dpopJkt = null): IssuedToken;

    /**
     * A token for a user in the context of a client (e.g. after an SSO login).
     *
     * @param  list<string>  $scopes
     * @param  string|null  $resource  RFC 8707 resource indicator (see above)
     * @param  string|null  $dpopJkt  RFC 9449 DPoP binding (see above)
     */
    public function issueForUser(Client $client, string $userId, ?string $organizationId, array $scopes = [], ?string $resource = null, ?string $dpopJkt = null): IssuedToken;

    /**
     * A token for a user that somebody ELSE is holding — a support session (RFC 8693).
     *
     * The same token {@see issueForUser()} mints, plus the `act` claim naming the actor,
     * with a lifetime that never runs past `$notAfter` (the session's end), and recorded
     * against the session so ending it revokes the token.
     *
     * @param  list<string>  $scopes
     */
    public function issueActing(
        Client $client,
        string $userId,
        ?string $organizationId,
        array $scopes,
        ActingParty $actor,
        DateTimeInterface $notAfter,
        ?string $resource = null,
        ?string $dpopJkt = null,
    ): IssuedToken;
}
