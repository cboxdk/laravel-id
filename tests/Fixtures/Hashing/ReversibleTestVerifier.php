<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures\Hashing;

use Cbox\Id\Identity\Contracts\HashVerifier;

/**
 * A deliberately trivial, NON-CRYPTOGRAPHIC stand-in for a host-provided verifier
 * (e.g. a Firebase-scrypt or PBKDF2 wrapper), used only to prove the extension
 * seam and lazy migration for a foreign format WITHOUT pulling a real legacy
 * hashing library into the test suite. Its "hash" is `rev$` followed by the
 * reversed password. Never use anything like this in production — the point of
 * the seam is that a real host wraps a VETTED library here.
 */
class ReversibleTestVerifier implements HashVerifier
{
    private const PREFIX = 'rev$';

    public static function hash(string $password): string
    {
        return self::PREFIX.strrev($password);
    }

    public function supports(string $hash): bool
    {
        return str_starts_with($hash, self::PREFIX);
    }

    public function verify(string $password, string $hash): bool
    {
        if (! $this->supports($hash)) {
            return false;
        }

        return hash_equals($hash, self::hash($password));
    }

    public function needsRehash(string $hash): bool
    {
        // A foreign format is always a candidate for upgrade to the platform hasher.
        return true;
    }
}
