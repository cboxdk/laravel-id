<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Contracts;

use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\ValueObjects\RegisteredDirectory;

interface Directories
{
    public function register(string $organizationId, string $name): RegisteredDirectory;

    /**
     * Register an API-pull directory (Google Workspace, Entra, …). The provider
     * credentials are sealed at rest (Crypto SecretBox), bound to the directory id.
     *
     * @param  array<string, mixed>  $credentials
     */
    public function registerPull(string $organizationId, string $name, DirectoryProvider $provider, array $credentials): Directory;

    /**
     * Resolve a directory by a presented SCIM bearer token (constant-time), or null.
     */
    public function authenticate(string $token): ?Directory;
}
