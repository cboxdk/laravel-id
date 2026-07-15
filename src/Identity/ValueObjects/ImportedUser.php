<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Contracts\HashVerifier;

/**
 * One user to import from another provider (Auth0/Cognito/Firebase/a CSV export).
 *
 * The credential is the whole point of the migration wedge:
 *   - {@see $passwordHash} — the provider's EXISTING hash, stored verbatim so the
 *     user signs in on day one and the hash is transparently upgraded to the
 *     platform hasher on their first successful login (lazy migration). Its
 *     format must be verifiable by a registered
 *     {@see HashVerifier} (native = bcrypt/argon2).
 *   - {@see $password} — a plaintext password, hashed with the platform hasher
 *     immediately (no legacy hash to carry).
 *
 * Provide at most one of the two. A row with neither is imported without a
 * password credential (the user signs in via SSO, a magic link, or a reset).
 */
final readonly class ImportedUser
{
    /**
     * @param  array<string, mixed>  $attributes  provider-specific extras, carried
     *                                            through untouched for the host
     */
    public function __construct(
        public string $email,
        public ?string $name = null,
        public ?string $passwordHash = null,
        public ?string $password = null,
        public bool $emailVerified = false,
        public array $attributes = [],
        public ?string $role = null,
    ) {}
}
