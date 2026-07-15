<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Hashing;

use Cbox\Id\Identity\Contracts\HashVerifier;

/**
 * The one verifier the package ships: the natively-supported password families,
 * verified through PHP's vetted `password_verify` / `password_needs_rehash`.
 * Nothing here is hand-rolled — the crypto is the platform runtime's.
 *
 * Covers the formats `password_hash()` produces:
 *   - bcrypt  — `$2y$…`, `$2a$…`, `$2b$…`
 *   - argon2  — `$argon2i$…`, `$argon2id$…`
 *
 * These are exactly the formats Auth0/Cognito/most SQL apps export, so the common
 * migration path needs no host code at all. Weak legacy digests (raw md5/sha1,
 * `{SSHA}`, PBKDF2, Firebase scrypt) are deliberately NOT supported here: a host
 * that must accept one registers its own {@see HashVerifier} wrapping a vetted
 * library, opting in explicitly rather than the package quietly trusting a weak
 * or non-native format.
 */
class NativePasswordVerifier implements HashVerifier
{
    /**
     * @param  string  $algorithm  the platform's target algorithm (a `PASSWORD_*`
     *                             constant) — what a verified hash is upgraded TO
     * @param  array<string, int>  $options  the target algorithm's cost options,
     *                                       mirroring the platform hasher's config
     */
    public function __construct(
        private readonly string $algorithm,
        private readonly array $options = [],
    ) {}

    public function supports(string $hash): bool
    {
        // password_get_info recognizes exactly the families password_hash emits;
        // an algo of null (0 as a legacy value) means "not a native hash".
        $info = password_get_info($hash);
        $algo = $info['algo'];

        return $algo !== null && $algo !== 0 && $algo !== '';
    }

    public function verify(string $password, string $hash): bool
    {
        // Deny-by-default: never hand a non-native format to password_verify with
        // the hope it "might" match — an unrecognized format is a rejection.
        if (! $this->supports($hash)) {
            return false;
        }

        return password_verify($password, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        if (! $this->supports($hash)) {
            // Unknown to this verifier — it is, by definition, not the current
            // native standard, so it should be replaced once we can.
            return true;
        }

        return password_needs_rehash($hash, $this->algorithm, $this->options);
    }
}
