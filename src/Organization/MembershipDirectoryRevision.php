<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use LogicException;

/** A membership mutation and its public outbox record commit at the same organization revision. */
final class MembershipDirectoryRevision
{
    public static function advance(string $organization): int
    {
        $row = self::row($organization);
        $row->increment('revision');

        return self::number($row->value('revision'));
    }

    /** Hold until the page query completes so pagination metadata describes the rows actually read. */
    public static function snapshot(string $organization): int
    {
        return self::number(self::row($organization)->sharedLock()->value('revision'));
    }

    private static function row(string $organization): Builder
    {
        if (DB::transactionLevel() < 1) {
            throw new LogicException('Directory revisions require the membership transaction.');
        }
        DB::table('membership_directory_revisions')->insertOrIgnore(['organization_id' => $organization, 'revision' => 0]);

        return DB::table('membership_directory_revisions')->where('organization_id', $organization);
    }

    private static function number(mixed $value): int
    {
        if (! is_numeric($value)) {
            throw new LogicException('Membership directory revision missing.');
        }

        return intval($value);
    }
}
