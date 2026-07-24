<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\ValueObjects;

use Cbox\Id\Platform\Models\EnvironmentApiKey;

/**
 * The result of issuing an environment API key: the stored record plus the one-time
 * plaintext. The plaintext exists only here — it is never persisted and cannot be
 * recovered, so the caller must surface it to the user immediately.
 */
readonly class IssuedEnvironmentApiKey
{
    public function __construct(
        public EnvironmentApiKey $key,
        public string $plaintext,
    ) {}
}
