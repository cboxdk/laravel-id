<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Contracts;

use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectorySort;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\DirectoryPage;
use Cbox\Id\Directory\ValueObjects\DirectorySearch;

/**
 * The full SCIM list query over a directory's users — filter, pagination AND sorting.
 *
 * An optional capability of a {@see DirectoryUsers} store, not a replacement for it:
 * the SCIM layer checks whether the bound `DirectoryUsers` also implements this, and
 * falls back to `list()` (refusing a `sortBy` it then cannot honour) when it does not.
 * A host that rebound `DirectoryUsers` to its own store therefore keeps working
 * unchanged, and opts into sorting by implementing this as well.
 */
interface DirectoryUserSearch
{
    /**
     * @return DirectoryPage<DirectoryUser>
     *
     * @throws UnsupportedDirectoryFilter
     * @throws UnsupportedDirectorySort
     */
    public function search(Directory $directory, DirectorySearch $search): DirectoryPage;
}
