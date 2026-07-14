<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Contracts;

use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\DirectoryPage;

/**
 * Read-side access to the synced {@see DirectoryUser} resources of a directory —
 * the SCIM list/filter/pagination and single-resource lookup, kept out of the
 * HTTP layer so the controller only validates and maps.
 */
interface DirectoryUsers
{
    /**
     * A filtered, paginated page of the directory's users. `$filter` is a SCIM
     * filter expression (empty for none); `$startIndex`/`$count` are the SCIM
     * pagination parameters (null when the client omitted them). The returned page
     * carries the effective, clamped start index for the response envelope.
     *
     * @return DirectoryPage<DirectoryUser>
     *
     * @throws UnsupportedDirectoryFilter
     */
    public function list(Directory $directory, string $filter, ?int $startIndex, ?int $count): DirectoryPage;

    /**
     * A single user resource scoped to the directory, or null when absent.
     */
    public function find(Directory $directory, string $id): ?DirectoryUser;
}
