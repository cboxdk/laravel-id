<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\HashVerifier;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Contracts\UserImport;
use Cbox\Id\Identity\ValueObjects\ImportedUser;
use Cbox\Id\Identity\ValueObjects\ImportError;
use Cbox\Id\Identity\ValueObjects\ImportOptions;
use Cbox\Id\Identity\ValueObjects\ImportResult;
use Cbox\Id\Identity\ValueObjects\Subject;
use Cbox\Id\Organization\Contracts\Memberships;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * The default {@see UserImport}: provisions imported users into the platform's own
 * store via {@see Subjects} and attaches each to an organization via
 * {@see Memberships}. It runs in the AMBIENT environment scope (like every other
 * platform service), so the caller establishes which environment the users land
 * in — the CLI resolves it from the target organization.
 *
 * Guarantees:
 *   - honest-crypto — a plaintext password is hashed by the platform hasher now; a
 *     pre-hashed credential is stored verbatim ({@see Subjects::storeCredential()})
 *     for lazy migration. Nothing is hand-hashed here.
 *   - deny-by-default — with {@see ImportOptions::$rejectUnverifiableHashes} a
 *     credential no registered {@see HashVerifier} supports is a per-row error, so
 *     you can't import an account that could never log in.
 *   - idempotent — an existing email is skipped, or upserted per the options.
 *   - resilient — rows are batched per chunk in a transaction, each row is atomic
 *     (a savepoint), and a failing row is collected as an error, never aborting
 *     the run.
 */
class DatabaseUserImport implements UserImport
{
    public function __construct(
        private readonly Subjects $subjects,
        private readonly Memberships $memberships,
        private readonly HashVerifier $verifier,
    ) {}

    public function import(string $organizationId, iterable $users, ImportOptions $options): ImportResult
    {
        $imported = 0;
        $updated = 0;
        $skipped = 0;

        /** @var list<ImportError> $errors */
        $errors = [];

        $row = 0;
        /** @var list<array{index: int, user: ImportedUser}> $chunk */
        $chunk = [];

        $flush = function () use (&$chunk, $organizationId, $options, &$imported, &$updated, &$skipped, &$errors): void {
            if ($chunk === []) {
                return;
            }

            // One transaction per chunk (batching); each row is wrapped in its own
            // nested transaction (savepoint) so a mid-row failure rolls back just
            // that row, never the whole chunk.
            DB::transaction(function () use (&$chunk, $organizationId, $options, &$imported, &$updated, &$skipped, &$errors): void {
                foreach ($chunk as $entry) {
                    $this->provision($entry['index'], $entry['user'], $organizationId, $options, $imported, $updated, $skipped, $errors);
                }
            });

            $chunk = [];
        };

        foreach ($users as $user) {
            $row++;
            $chunk[] = ['index' => $row, 'user' => $user];

            if (count($chunk) >= max(1, $options->chunkSize)) {
                $flush();
            }
        }

        $flush();

        return new ImportResult($imported, $updated, $skipped, $errors);
    }

    /**
     * @param  list<ImportError>  $errors
     */
    private function provision(
        int $index,
        ImportedUser $user,
        string $organizationId,
        ImportOptions $options,
        int &$imported,
        int &$updated,
        int &$skipped,
        array &$errors,
    ): void {
        $email = trim($user->email);

        if ($email === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = new ImportError($index, $email, 'Invalid email address.');

            return;
        }

        // Deny-by-default credential validation, BEFORE any write: a pre-hashed
        // credential nothing can verify would import a user who can never log in.
        if ($user->passwordHash !== null && $options->rejectUnverifiableHashes && ! $this->verifier->supports($user->passwordHash)) {
            $errors[] = new ImportError($index, $email, 'Unsupported password hash format — register a HashVerifier for it, or drop the hash.');

            return;
        }

        try {
            DB::transaction(function () use ($user, $email, $organizationId, $options, &$imported, &$updated, &$skipped): void {
                $existing = $this->subjects->findByEmail($email);

                if ($existing !== null) {
                    if (! $options->upsert) {
                        $skipped++;

                        return;
                    }

                    $this->applyCredential($existing->id, $user);
                    $this->attach($organizationId, $existing->id, $user, $options);
                    $updated++;

                    return;
                }

                $subject = $this->createSubject($email, $user);
                $this->attach($organizationId, $subject->id, $user, $options);
                $imported++;
            });
        } catch (Throwable $e) {
            $errors[] = new ImportError($index, $email, $e->getMessage());
        }
    }

    private function createSubject(string $email, ImportedUser $user): Subject
    {
        // A plaintext password is hashed by the platform hasher at creation; a
        // pre-hashed credential is created without a password, then stored verbatim.
        $subject = $this->subjects->create($email, $user->name, $user->password);

        if ($user->password === null && $user->passwordHash !== null) {
            $this->subjects->storeCredential($subject->id, $user->passwordHash);
        }

        return $subject;
    }

    private function applyCredential(string $subjectId, ImportedUser $user): void
    {
        if ($user->password !== null) {
            $this->subjects->setPassword($subjectId, $user->password);

            return;
        }

        if ($user->passwordHash !== null) {
            $this->subjects->storeCredential($subjectId, $user->passwordHash);
        }
    }

    private function attach(string $organizationId, string $subjectId, ImportedUser $user, ImportOptions $options): void
    {
        $role = $user->role !== null && $user->role !== '' ? $user->role : $options->defaultRole;
        $this->memberships->add($organizationId, $subjectId, $role);

        if ($options->markEmailVerified && $user->emailVerified) {
            $this->subjects->markEmailVerified($subjectId, trim($user->email));
        }
    }
}
