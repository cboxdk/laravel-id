<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

final readonly class IssuedToken
{
    public function __construct(
        public string $token,
        public string $jti,
        public int $expiresIn,
    ) {}
}
