<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Models\Client;

/**
 * Verifies a `private_key_jwt` client-authentication assertion (RFC 7523 / OIDC
 * Core §9) against the client's registered JWK Set. Behind a contract so a host can
 * adjust the accepted algorithms, jti storage, or audience policy without forking
 * the security-critical verifier — client authentication is exactly the kind of
 * capability that should be swappable.
 */
interface ClientAssertion
{
    /** RFC 7521 client-assertion type for a JWT bearer assertion. */
    public const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /**
     * The authenticated client, or null for anything invalid (unknown client, no
     * registered keys, bad signature/alg, wrong audience, expired/over-long,
     * replayed, or iss≠sub).
     */
    public function verify(string $assertion): ?Client;
}
