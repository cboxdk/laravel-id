<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

final readonly class IssuedToken
{
    public function __construct(
        public string $token,
        public string $jti,
        public int $expiresIn,
        // "Bearer", or "DPoP" when sender-constrained to a client key (RFC 9449).
        public string $tokenType = 'Bearer',
    ) {}
}
