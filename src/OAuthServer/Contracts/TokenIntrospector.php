<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\ValueObjects\Introspection;

interface TokenIntrospector
{
    /**
     * Verify a token's signature (alg-allowlisted), expiry and revocation state.
     * Returns an inactive result for anything untrusted — never throws on bad input.
     */
    public function introspect(string $token): Introspection;

    public function revoke(string $jti): void;
}
