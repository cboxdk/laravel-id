<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Contracts\OidcRelyingParty;
use Cbox\Id\Federation\Contracts\OidcTokenExchange;

/**
 * What an OpenID Provider's token endpoint answered, as far as sign-in needs it.
 *
 * {@see OidcRelyingParty::exchangeCode()} returns the `id_token` alone, which is all a
 * provider that puts the identity in the token ever needs. Intuit does not: its
 * `id_token` carries no address, and the address is behind the UserInfo endpoint, which
 * takes the ACCESS token (OpenID Connect Core §5.3.1). So the exchange that can feed
 * UserInfo returns both — see {@see OidcTokenExchange}.
 *
 * The access token is never stored. It lives for the length of one callback, long enough
 * to ask UserInfo who the person is, and is dropped with this object.
 */
readonly class OidcTokenSet
{
    public function __construct(
        public string $idToken,

        /** Null when the provider answered without one; UserInfo is then unreachable. */
        public ?string $accessToken = null,
    ) {}
}
