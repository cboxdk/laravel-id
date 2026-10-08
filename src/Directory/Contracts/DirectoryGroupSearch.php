<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Contracts;

use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectorySort;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\ValueObjects\DirectoryPage;
use Cbox\Id\Directory\ValueObjects\DirectorySearch;

/**
 * The full SCIM list query over a directory's groups — filter, pagination AND sorting.
 * An optional capability of a {@see DirectoryGroups} store; see
 * {@see DirectoryUserSearch} for how the SCIM layer uses it.
 *
 * `$withMembers` has the meaning it has on {@see DirectoryGroups::list()}.
 */
interface DirectoryGroupSearch
{
    /**
     * @return DirectoryPage<DirectoryGroup>
     *
     * @throws UnsupportedDirectoryFilter
     * @throws UnsupportedDirectorySort
     */
    public function search(Directory $directory, DirectorySearch $search, bool $withMembers = false): DirectoryPage;
}
