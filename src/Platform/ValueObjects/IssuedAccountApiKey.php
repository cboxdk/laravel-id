<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\ValueObjects;

use Cbox\Id\Platform\Models\AccountApiKey;

/**
 * The result of issuing an account API key: the stored record plus the one-time
 * plaintext. The plaintext exists only here — it is never persisted and cannot be
 * recovered, so the caller must surface it to the user immediately.
 */
readonly class IssuedAccountApiKey
{
    public function __construct(
        public AccountApiKey $key,
        public string $plaintext,
    ) {}
}
