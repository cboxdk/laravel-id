<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\ImportedUser;
use Cbox\Id\Identity\ValueObjects\ImportOptions;
use Cbox\Id\Identity\ValueObjects\ImportResult;
use Cbox\Id\Organization\Contracts\Memberships;

/**
 * Bulk-imports users — including their EXISTING password hashes — from another
 * provider so they can sign in immediately, with each foreign hash transparently
 * upgraded to the platform hasher on the user's first successful login (see
 * {@see Subjects::verifyPassword()} and {@see HashVerifier}). This is the
 * enterprise migration wedge: move off Auth0/Cognito/Firebase/a legacy SQL app
 * without a forced password reset.
 *
 * The default implementation provisions into the platform's own user store via
 * {@see Subjects} and attaches each user to an organization via
 * {@see Memberships}. A host with its own user
 * store binds its own implementation.
 */
interface UserImport
{
    /**
     * Import a stream of users into the given organization within the current
     * environment scope. Idempotent per email (skip or upsert per
     * {@see ImportOptions::$upsert}); rows are batched in a transaction per chunk
     * and per-row failures are collected into {@see ImportResult}, never aborting
     * the whole run.
     *
     * @param  iterable<ImportedUser>  $users
     */
    public function import(string $organizationId, iterable $users, ImportOptions $options): ImportResult;
}
