<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\ValueObjects\OidcTokenSet;

/**
 * The code exchange that keeps the access token as well as the `id_token`.
 *
 * A separate contract rather than a new method on {@see OidcRelyingParty}, because a host
 * may implement that interface and adding to it would break the host. The shipped
 * client implements both; the callback asks for this one when the bound relying party
 * offers it and falls back to `exchangeCode()` when it does not — in which case a
 * provider that needs UserInfo signs people in without the claims only UserInfo holds,
 * exactly as it did before this existed.
 */
interface OidcTokenExchange
{
    /**
     * @throws InvalidAssertion when the connection is incomplete, the token endpoint is
     *                          refused by the SSRF gate, or the exchange fails
     * @throws UnsafeFederationUrl
     */
    public function exchange(Connection $connection, string $code, string $redirectUri): OidcTokenSet;
}
