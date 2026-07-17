<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Contracts;

use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\ValueObjects\DirectoryGroupSnapshot;
use Cbox\Id\Directory\ValueObjects\ScimUser;

/**
 * An API-pull directory connector — fetches the current user set from a provider's
 * API (Google Admin SDK, Microsoft Graph, …) and yields them as {@see ScimUser}s so
 * they flow through the SAME reconciliation ({@see DirectorySync}) as SCIM-push
 * users. Credentials are the decrypted, provider-specific secret map (never stored
 * here — the caller unseals them per pull).
 */
interface DirectoryConnector
{
    public function provider(): DirectoryProvider;

    /**
     * The full current set of users in the provider's directory. Implementations
     * page through the provider's API transparently.
     *
     * @param  array<string, mixed>  $credentials
     * @return iterable<ScimUser>
     *
     * @throws DirectoryConnectionFailed
     */
    public function fetchUsers(array $credentials): iterable;

    /**
     * The full current set of groups (with member external ids). A provider without
     * group support yields nothing.
     *
     * @param  array<string, mixed>  $credentials
     * @return iterable<DirectoryGroupSnapshot>
     *
     * @throws DirectoryConnectionFailed
     */
    public function fetchGroups(array $credentials): iterable;

    /**
     * Verify the credentials reach the provider (a cheap probe), without a full
     * sync — used when an admin connects the directory.
     *
     * @param  array<string, mixed>  $credentials
     */
    public function verify(array $credentials): bool;
}
