<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Contracts;

use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\ValueObjects\RegisteredDirectory;

interface Directories
{
    public function register(string $organizationId, string $name): RegisteredDirectory;

    /**
     * Resolve a directory by a presented SCIM bearer token (constant-time), or null.
     */
    public function authenticate(string $token): ?Directory;
}
