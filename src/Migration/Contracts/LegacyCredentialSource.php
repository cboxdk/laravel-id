<?php

declare(strict_types=1);

namespace Cbox\Id\Migration\Contracts;

use Cbox\Id\Identity\ValueObjects\ImportedUser;

/**
 * Somewhere else that still knows a person's password.
 *
 * BULK IMPORT IS THE FIRST ANSWER, AND IT IS BETTER. {@see UserImport} moves users with
 * their existing hashes in one pass, and each hash is upgraded on first login. Nobody
 * notices, and the old system can be switched off the same day.
 *
 * It requires that you can EXPORT the hashes, and often you cannot: they sit in a system
 * with no dump, or in a format nothing recognises, or behind an API somebody else owns.
 * That is what this is for. Instead of moving the data, the verification moves: an email
 * nobody here knows is offered to the old system, and if it answers yes the person is
 * imported as a RESULT of the login that just succeeded.
 *
 * The two are complementary. Import everyone you can, delegate the remainder, and switch
 * the old system off when the tail is thin enough to be worth a password reset.
 *
 * TWO RULES THIS CONTRACT EXISTS TO ENFORCE, both of which are security properties and
 * neither of which is obvious:
 *
 *  1. A LOCAL USER IS NEVER OFFERED HERE. Once somebody exists in this platform, their
 *     password is the one in this platform, full stop. Consulting the old system for a
 *     user who has already migrated would let a password they changed HERE be bypassed
 *     by the one still sitting THERE — and the old system is, by definition, the one
 *     nobody is maintaining any more.
 *
 *  2. UNAVAILABILITY FAILS CLOSED. If the old system is down or slow, an un-migrated
 *     person cannot sign in. The alternative — letting them through because we could not
 *     check — turns an outage in the system you are migrating off into an authentication
 *     bypass. Migrated users are unaffected, because rule 1 means they never come near
 *     this path, so the blast radius is exactly the tail you have not moved yet.
 */
interface LegacyCredentialSource
{
    /**
     * Does the old system accept this email and password?
     *
     * Returns the person as the old system knows them — enough to create them here — or
     * null for "no". Null must cover every failure the caller treats identically:
     * unknown user, wrong password, malformed record. Distinguishing them to the caller
     * would rebuild the enumeration oracle the login form spent effort closing.
     *
     * MUST NOT throw for a wrong password. An exception means "I could not decide",
     * which the caller turns into a refusal — see rule 2 above.
     */
    public function verify(string $email, string $password): ?ImportedUser;

    /**
     * Does the old system know this email at all, without checking a password?
     *
     * Used by tooling — a migration progress report, a dry run before cutover — and never
     * by the login path, because "does this account exist" answered to an anonymous
     * caller is precisely the oracle we refuse to build.
     */
    public function find(string $email): ?ImportedUser;
}
