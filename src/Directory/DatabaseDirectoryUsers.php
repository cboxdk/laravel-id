<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\DirectoryUsers;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\Support\ScimUserFilter;
use Cbox\Id\Directory\ValueObjects\DirectoryPage;

/**
 * The default {@see DirectoryUsers} read model over the `directory_users` table:
 * SCIM filter translation and pagination live here, not in the HTTP controller.
 */
final class DatabaseDirectoryUsers implements DirectoryUsers
{
    private const MAX_PAGE = 200;

    public function list(Directory $directory, string $filter, ?int $startIndex, ?int $count): DirectoryPage
    {
        $query = DirectoryUser::query()->where('directory_id', $directory->id);

        if ($filter !== '') {
            $parsed = ScimUserFilter::parse($filter);

            if ($parsed === null) {
                throw UnsupportedDirectoryFilter::make($filter);
            }

            $parsed->apply($query);
        }

        $total = (clone $query)->count();

        $start = max(1, $startIndex ?? 1);
        $limit = min(self::MAX_PAGE, max(0, $count ?? self::MAX_PAGE));

        $resources = $query->orderBy('id')->offset($start - 1)->limit($limit)->get();

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
