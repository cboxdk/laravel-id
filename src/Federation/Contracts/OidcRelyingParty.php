<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Federation\Models\Connection;

/**
 * The relying-party half of an OIDC connection: build the authorization request the
 * browser is sent to, and exchange the returned code for an `id_token`.
 *
 * Published as a contract for the same reason every other Federation collaborator is
 * ({@see Connections}, {@see FederationFlow}, {@see AssertionValidator}): the HTTP
 * controllers should depend on the module's surface, not reach past it into a
 * concrete class. Signature and claim validation of the resulting token belongs to
 * {@see AssertionValidator}, not here.
 */
interface OidcRelyingParty
{
    /**
     * @throws InvalidAssertion when the connection has no authorization endpoint
     */
    public function authorizeUrl(Connection $connection, string $redirectUri, string $state, string $nonce): string;

    /**
     * Exchange an authorization code for the `id_token`.
     *
     * @throws InvalidAssertion when the connection is incomplete, the token endpoint
     *                          is refused by the SSRF gate, or the exchange fails
     * @throws UnsafeFederationUrl
     */
    public function exchangeCode(Connection $connection, string $code, string $redirectUri): string;
}
