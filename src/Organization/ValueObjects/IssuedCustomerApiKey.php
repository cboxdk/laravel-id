<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

use Cbox\Id\Organization\Models\CustomerApiKey;

/**
 * The result of issuing a customer API key: the persisted record plus the plaintext,
 * available exactly once — it is never stored and cannot be re-derived.
 */
readonly class IssuedCustomerApiKey
{
    public function __construct(
        public CustomerApiKey $key,
        public string $plaintext,
    ) {}
}
