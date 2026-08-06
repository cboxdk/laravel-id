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
     * Resolve a directory by a presented SCIM bearer token, or null.
     *
     * The lookup is an indexed match on the token's SHA-256, NOT a constant-time
     * comparison — this docblock claimed otherwise and the implementation never did it.
     * The timing that leaks is the index probe, which distinguishes a hash that exists
     * from one that does not; it does not narrow a partial guess, because the attacker
     * controls the pre-image and the digest of a 256-bit random secret is not
     * incrementally guessable. So this is honest rather than exploitable — but do not
     * reintroduce a shorter or lower-entropy token on the strength of the old claim.
     */
    public function authenticate(string $token): ?Directory;
}
