<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Models\StoredClientSecret;

/**
 * A secret just written to a client: the minted value (plaintext readable once) and the
 * row that now holds its hash.
 */
readonly class IssuedClientSecret
{
    public function __construct(
        public ClientSecret $secret,
        public StoredClientSecret $stored,
    ) {}
}
