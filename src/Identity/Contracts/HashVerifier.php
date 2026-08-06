<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Hashing\HashVerifierRegistry;

/**
 * Verifies a plaintext password against a stored password hash of a specific
 * format. This is the seam that makes lazy password-hash migration possible: a
 * user imported from another provider carries that provider's hash verbatim, and
 * a verifier that understands the format lets them sign in on day one — after
 * which the platform transparently re-hashes their password with its own hasher.
 *
 * The default registry ({@see HashVerifierRegistry}) is
 * DENY-BY-DEFAULT: a hash whose format no registered verifier {@see supports()}
 * fails {@see verify()} — it is NEVER a silent pass. The package ships only the
 * native verifier (bcrypt + argon2, backed by PHP's vetted `password_verify`); a
 * host adds a format (Firebase scrypt, PBKDF2, …) by registering its own verifier
 * that wraps a vetted library — never by hand-rolling the primitive here.
 */
interface HashVerifier
{
    /**
     * Whether this verifier recognizes the hash's format and can therefore make a
     * meaningful accept/reject decision about it. A verifier that returns false
     * here MUST also return false from {@see verify()} for the same hash.
     */
    public function supports(string $hash): bool;

    /**
     * Constant-time-as-the-primitive check of the password against the hash.
     * Returns false for any hash this verifier does not {@see supports()} — an
     * unrecognized format is a rejection, never a silent pass.
     */
    public function verify(string $password, string $hash): bool;

    /**
     * Whether the stored hash should be upgraded to the platform's current
     * hashing standard (a foreign/legacy format, or the platform algorithm with
     * weaker parameters than currently configured). Consulted only after a
     * successful {@see verify()}, to drive transparent re-hashing on login.
     */
    public function needsRehash(string $hash): bool;
}
