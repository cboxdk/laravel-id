<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Contracts;

use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Exceptions\InvalidToken;
use Cbox\Id\Kernel\Crypto\ValueObjects\TokenClaims;

/**
 * Signs and verifies JWTs using the platform's managed signing keys.
 */
interface TokenSigner
{
    /**
     * @param  array<string, mixed>  $claims
     * @param  string|null  $type  the JWT `typ` header (e.g. `at+jwt` for an OAuth
     *                             access token, RFC 9068); omit for a plain JWT
     */
    public function sign(array $claims, ?SigningAlg $alg = null, ?string $type = null): string;

    /**
     * Verify signature, expiry and — critically — that the token's algorithm is
     * one of the explicitly allowed algorithms. The allow-list is REQUIRED and
     * never inferred from the token header, which is what defeats `alg=none`
     * and RS↔HS confusion.
     *
     * @param  list<SigningAlg>  $allowed  at least one algorithm; an empty list is rejected
     *
     * @throws InvalidToken
     */
    public function verify(string $jwt, array $allowed): TokenClaims;
}
