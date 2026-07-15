<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Testing;

use Cbox\Id\Identity\Contracts\UserImport;
use Cbox\Id\Identity\ValueObjects\ImportedUser;
use Cbox\Id\Identity\ValueObjects\ImportOptions;
use Cbox\Id\Identity\ValueObjects\ImportResult;

/**
 * Test ergonomics for the bulk user import:
 *
 *     $result = $this->importUsers($org->id, [
 *         $this->importedUser('alice@corp.test', passwordHash: password_hash('pw', PASSWORD_BCRYPT)),
 *     ]);
 *
 * Ships with the package (not test-only) so a downstream host gets the same
 * fluency when it dogfoods the import in its own suite.
 */
trait InteractsWithImport
{
    protected function importedUser(
        string $email,
        ?string $name = null,
        ?string $passwordHash = null,
        ?string $password = null,
        bool $emailVerified = false,
        ?string $role = null,
    ): ImportedUser {
        return new ImportedUser(
            email: $email,
            name: $name,
            passwordHash: $passwordHash,
            password: $password,
            emailVerified: $emailVerified,
            role: $role,
        );
    }

    /**
     * @param  iterable<ImportedUser>  $users
     */
    protected function importUsers(string $organizationId, iterable $users, ?ImportOptions $options = null): ImportResult
    {
        return app(UserImport::class)->import($organizationId, $users, $options ?? new ImportOptions);
    }
}
