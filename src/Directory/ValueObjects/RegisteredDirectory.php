<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\ValueObjects;

use Cbox\Id\Directory\Models\Directory;

/**
 * Returned once at registration: the directory plus its plaintext SCIM bearer
 * token, which is never retrievable again (only its hash is stored).
 */
readonly class RegisteredDirectory
{
    public function __construct(
        public Directory $directory,
        public string $token,
    ) {}
}
