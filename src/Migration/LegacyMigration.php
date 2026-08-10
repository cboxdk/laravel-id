<?php

declare(strict_types=1);

namespace Cbox\Id\Migration;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\ValueObjects\ImportedUser;
use Cbox\Id\Identity\ValueObjects\Subject;
use Cbox\Id\Migration\Contracts\LegacyCredentialSource;
use Cbox\Id\Migration\Events\UserMigrated;
use Illuminate\Contracts\Events\Dispatcher;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Moving one person, at the moment they prove they are still that person.
 *
 * This is the whole delegated-authentication flow, and it is deliberately small: ask the
 * old system, and if it says yes, create them here. Everything after that — sessions,
 * MFA, lockout, audit — is the platform's ordinary login path, because from the second
 * row onwards they are an ordinary user.
 *
 * WHERE IT SITS. The caller looks for a local user first and only reaches this when there
 * is none. That ordering is not an optimisation, it is rule 1 on
 * {@see LegacyCredentialSource}: a person who exists here authenticates against what is
 * here, and the old system — the one nobody is maintaining any more — never gets a second
 * vote on a password they may have changed since.
 *
 * WHAT HAPPENS TO TIMING. An unknown email now costs a database read or an HTTP hop that a
 * known one does not, which is a new enumeration signal if the work is skipped for
 * addresses the legacy system does not know. It is not skipped: the source is asked for
 * every unknown address and answers null at the same cost either way. The bridge is also
 * consulted only when a local user is absent, so the population this timing describes is
 * "not yet migrated", not "does not exist".
 */
class LegacyMigration
{
    public function __construct(
        private readonly LegacyCredentialSource $source,
        private readonly Subjects $subjects,
        private readonly Dispatcher $events,
        private readonly LoggerInterface $log,
    ) {}

    /**
     * Verify against the old system and, on success, create the person here.
     *
     * Returns the newly created subject, or null — which the caller must treat exactly
     * as it treats a wrong password, with the same timing work and the same message.
     */
    public function migrate(string $email, string $password): ?Subject
    {
        $imported = $this->verifySafely($email, $password);

        if ($imported === null) {
            return null;
        }

        try {
            // Created WITHOUT a password, then given the credential separately — because
            // the two ways of carrying it are not interchangeable and `create()` hashes
            // what it is handed. Passing a foreign hash there would hash the hash, and
            // the person's password would silently stop working the moment they migrated:
            // a failure that looks exactly like them mistyping it.
            $subject = $this->subjects->create(
                email: $imported->email,
                name: $imported->name,
            );

            if ($imported->passwordHash !== null) {
                // Verbatim. `storeCredential` is the import path: it does not re-hash, so
                // a foreign format survives and is upgraded to the platform hasher on the
                // next successful login — exactly what a bulk-imported user gets.
                $this->subjects->storeCredential($subject->id, $imported->passwordHash);
            } else {
                // The old system proved the credential but cannot hand over its hash — an
                // opaque API, typically. Hashing what they just proved they know is the
                // only other honest option, and it lands them on the platform hasher
                // immediately rather than eventually.
                $this->subjects->setPassword($subject->id, $password);
            }
        } catch (Throwable $e) {
            // A race: two tabs, two requests, one wins the unique index. Losing that race
            // is not a failed login — the user now exists, and the caller's retry finds
            // them locally. Anything else is a real fault and must not become a silent
            // refusal, so it is logged with the address that triggered it.
            $existing = $this->subjects->findByEmail($email);

            if ($existing !== null) {
                return $existing;
            }

            $this->log->error('Legacy migration could not create the user.', [
                'email' => $email,
                'exception' => $e->getMessage(),
            ]);

            return null;
        }

        // Emitted so a host can attach the person to an organization, copy attributes the
        // platform has no column for, or simply count how much of the tail is left. It is
        // the seam that keeps this class from growing a policy it should not own.
        $this->events->dispatch(new UserMigrated($subject, $imported));

        return $subject;
    }

    /**
     * Ask the source, and turn any failure into "no".
     *
     * FAIL CLOSED, said in code. A source that throws has not said the password is wrong;
     * it has said it could not decide. Letting an undecided answer through would turn an
     * outage in the system being migrated off into an authentication bypass, so the
     * refusal is the same one a wrong password gets — and it is logged, because a spike
     * here is a migration that has stalled and nobody would otherwise notice.
     */
    private function verifySafely(string $email, string $password): ?ImportedUser
    {
        try {
            return $this->source->verify($email, $password);
        } catch (Throwable $e) {
            $this->log->warning('Legacy credential source failed; refusing the sign-in.', [
                'exception' => $e->getMessage(),
            ]);

            return null;
        }
    }
}
