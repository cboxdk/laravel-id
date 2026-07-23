<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

use Cbox\Id\Organization\Models\UserApiToken;

/**
 * The result of issuing a token: the persisted record plus the plaintext,
 * available exactly once — it is never stored and cannot be re-derived.
 */
readonly class IssuedUserApiToken
{
    public function __construct(
        public UserApiToken $token,
        public string $plaintext,
    ) {}
}
