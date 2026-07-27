<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Database;

use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Query\Expression as RawExpression;
use Illuminate\Support\Facades\Schema;

/**
 * The DEFAULT clause for a `json` column, in the dialect the target engine accepts.
 *
 * WHY THIS EXISTS
 * ---------------
 * `$table->json('settings')->default('{}')` compiles to `... json not null default
 * '{}'`, which MySQL rejects outright:
 *
 *     SQLSTATE[42000] 1101 BLOB, TEXT, GEOMETRY or JSON column 'settings'
 *     can't have a default value
 *
 * MySQL has never allowed a LITERAL default on those types. Since 8.0.13 it allows
 * an EXPRESSION default — the same value wrapped in parentheses — and that is the
 * only spelling it takes. So `php artisan migrate` died on `environments`, the fifth
 * table, and every MySQL install of this package was dead on arrival regardless of
 * what the docs promised.
 *
 * WHY DRIVER-AWARE, AND NOT "DROP THE DB DEFAULT"
 * ----------------------------------------------
 * The obvious alternative — delete the database default everywhere and let the
 * models supply `$attributes = ['settings' => '{}']` — was rejected. Production runs
 * Postgres. Those tables already exist with `DEFAULT '{}'` on them, so dropping the
 * default from the migration would leave a fresh install and an upgraded install
 * with structurally different schemas, and the difference would only be visible on a
 * write that bypasses Eloquent (`insert()`, a seeder, an ops fix-up in psql, a
 * `NOT NULL` column with no value). That trades a loud, first-migration MySQL
 * failure for a quiet Postgres divergence, which is the worse bug.
 *
 * Driver-awareness keeps the emitted DDL BYTE-IDENTICAL on Postgres, SQLite and SQL
 * Server — they all take the plain literal, and they are what production and CI have
 * always run — and changes only the MySQL/MariaDB branch, which previously produced
 * no schema at all. There is nothing to regress there.
 *
 * `JSON_OBJECT()` / `JSON_ARRAY()` is preferred over the equally legal `DEFAULT
 * ('{}')` because the latter is stored with whatever character-set introducer the
 * session happened to carry — MySQL 8.4 records it as `DEFAULT (_latin1'{}')` on a
 * latin1 client — so the same migration would leave a different `SHOW CREATE TABLE`
 * on two machines. The function form is charset-neutral.
 *
 * Verified 2026-07-27 against MySQL 8.4.10 and MariaDB 11.8.8: both accept the
 * expression form and both materialise `{}` / `[]` on insert.
 */
final class JsonDefault
{
    /**
     * The default for a json column holding an OBJECT — `{}`.
     */
    public static function emptyObject(): string|Expression
    {
        return self::supportsOnlyExpressionDefaults()
            ? new RawExpression('(json_object())')
            : '{}';
    }

    /**
     * The default for a json column holding an ARRAY — `[]`.
     */
    public static function emptyArray(): string|Expression
    {
        return self::supportsOnlyExpressionDefaults()
            ? new RawExpression('(json_array())')
            : '[]';
    }

    /**
     * Engines that refuse a literal DEFAULT on a json column.
     *
     * MariaDB's `json` is an alias for `longtext CHECK (json_valid(..))`, and MariaDB
     * does accept the literal — but it accepts the expression too, and a host may
     * point either the `mysql` or the `mariadb` driver at a MariaDB server. Treating
     * the family as one keeps a single schema across both spellings.
     */
    private static function supportsOnlyExpressionDefaults(): bool
    {
        return in_array(Schema::getConnection()->getDriverName(), ['mysql', 'mariadb'], true);
    }
}
