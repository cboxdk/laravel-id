<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Contracts;

use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Models\Directory;

/**
 * Changing a pull directory after it is connected: new credentials, a different pace, and —
 * for an HR system — which of its fields pass through onto people.
 *
 * Separate from {@see Directories} so that contract does not grow methods its existing
 * implementations would have to add; the package's own `DirectoryService` implements both.
 */
interface PullDirectories
{
    /**
     * Replace the sealed credentials. The caller verifies them against the provider first;
     * this only seals, bound to the directory id, exactly as registration does.
     *
     * @param  array<string, mixed>  $credentials
     *
     * @throws DirectoryConnectionFailed for a directory that is not a pull directory
     */
    public function replaceCredentials(Directory $directory, array $credentials): Directory;

    /**
     * How often the directory is pulled, in minutes, clamped to
     * {@see Directory::MIN_SYNC_INTERVAL_MINUTES}..{@see Directory::MAX_SYNC_INTERVAL_MINUTES};
     * null returns it to the configured default.
     */
    public function setSyncInterval(Directory $directory, ?int $minutes): Directory;

    /**
     * An HR system's field options, stored on `mappings.hris`: the provider's own field
     * names to pass through onto each person as custom attributes, and — for a system whose
     * columns the customer names (a Workday report) — our field => their column.
     *
     * @param  list<string>  $customAttributes
     * @param  array<string, string>  $fieldMap
     */
    public function setHrisOptions(Directory $directory, array $customAttributes, array $fieldMap = []): Directory;
}
