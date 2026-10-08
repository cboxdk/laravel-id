<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\DirectoryUsers;
use Cbox\Id\Directory\Contracts\DirectoryUserSearch;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\Support\ScimDirectoryQuery;
use Cbox\Id\Directory\Support\ScimQueryAttributes;
use Cbox\Id\Directory\ValueObjects\DirectoryPage;
use Cbox\Id\Directory\ValueObjects\DirectorySearch;

/**
 * The default {@see DirectoryUsers} read model over the `directory_users` table:
 * SCIM filter translation, sorting and pagination live here, not in the HTTP
 * controller.
 *
 * Filters are parsed by the full RFC 7644 §3.4.2.2 grammar and translated by
 * {@see ScimDirectoryQuery} over the attributes {@see ScimQueryAttributes::users()}
 * says this table holds.
 */
class DatabaseDirectoryUsers implements DirectoryUsers, DirectoryUserSearch
{
    private const MAX_PAGE = 200;

    public function list(Directory $directory, string $filter, ?int $startIndex, ?int $count): DirectoryPage
    {
        return $this->search($directory, new DirectorySearch($filter, $startIndex, $count));
    }

    public function search(Directory $directory, DirectorySearch $search): DirectoryPage
    {
        $query = DirectoryUser::query()->where('directory_id', $directory->id);

        (new ScimDirectoryQuery(ScimQueryAttributes::users()))->apply($query, $search);

        $total = (clone $query)->reorder()->count();

        $start = max(1, $search->startIndex ?? 1);
        $limit = min(self::MAX_PAGE, max(0, $search->count ?? self::MAX_PAGE));

        $resources = $query->offset($start - 1)->limit($limit)->get();

        return new DirectoryPage($resources, $total, $start);
    }

    public function find(Directory $directory, string $id): ?DirectoryUser
    {
        return DirectoryUser::query()
            ->where('directory_id', $directory->id)
            ->whereKey($id)
            ->first();
    }
}
