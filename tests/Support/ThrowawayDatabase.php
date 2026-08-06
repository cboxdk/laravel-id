<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Support;

use Closure;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * An empty database namespace the migrator can be pointed at, independent of the one
 * the suite itself runs on — so a test may migrate the package's entire schema up,
 * and back down, without disturbing the tables every other test is using.
 *
 * The isolation mechanism is per-engine, because "a second empty database" costs a
 * different privilege on each:
 *
 *   PostgreSQL  a throwaway SCHEMA on the same database. No CREATE DATABASE right
 *               needed, and `search_path` points the whole connection at it.
 *   MySQL /     a throwaway DATABASE. MySQL has no schema-below-database layer, so
 *   MariaDB     this is the only isolation available, and it does need the CREATE
 *               privilege — see the credentials note in the `engines` CI job.
 *   SQLite      a temporary file, next to (not inside) the suite's `:memory:` one.
 *
 * Created THROUGH a connection of its own rather than the suite's: on a server engine
 * each test runs inside a transaction, and a namespace created there would be
 * invisible to any other connection until it committed.
 */
final class ThrowawayDatabase
{
    /**
     * Open a throwaway namespace and return its connection name plus a cleanup.
     *
     * @return array{0: string, 1: Closure(): void} [connection name, cleanup]
     */
    public static function open(string $name = 'throwaway'): array
    {
        /** @var array<string, mixed> $base */
        $base = config('database.connections.testing');

        $driver = $base['driver'] ?? null;

        return match (true) {
            $driver === 'pgsql' => self::openPostgresSchema($base, $name),
            $driver === 'mysql' || $driver === 'mariadb' => self::openMysqlDatabase($base, $name),
            default => self::openSqliteFile($name),
        };
    }

    /**
     * Every base table in the throwaway namespace, as the engine reports it.
     *
     * Deliberately NOT `Schema::getTables()`: on PostgreSQL that enumerates every
     * non-system schema on the database, so it would also return the suite's own
     * tables and an emptiness assertion built on it could never pass.
     *
     * @return list<string>
     */
    public static function tables(string $connection): array
    {
        $driver = DB::connection($connection)->getDriverName();

        $rows = match ($driver) {
            'pgsql' => DB::connection($connection)->select(
                "select table_name as name from information_schema.tables where table_schema = current_schema() and table_type = 'BASE TABLE'",
            ),
            'mysql', 'mariadb' => DB::connection($connection)->select(
                "select table_name as name from information_schema.tables where table_schema = database() and table_type = 'BASE TABLE'",
            ),
            default => DB::connection($connection)->select(
                "select name from sqlite_master where type = 'table' and name not like 'sqlite_%'",
            ),
        };

        $names = array_map(
            fn (object $row): string => (string) ($row->name ?? $row->NAME ?? ''), // phpcs:ignore
            $rows,
        );

        sort($names);

        return array_values($names);
    }

    /**
     * @param  array<string, mixed>  $base
     * @return array{0: string, 1: Closure(): void}
     */
    private static function openPostgresSchema(array $base, string $name): array
    {
        $schema = $name.'_'.Str::lower(Str::random(12));

        config()->set('database.connections.'.$name, array_merge($base, ['search_path' => $schema]));
        DB::purge($name);

        // Postgres accepts a `search_path` naming a schema that does not exist yet,
        // so the connection can bootstrap its own.
        DB::connection($name)->statement('create schema "'.$schema.'"');

        return [$name, function () use ($name, $schema): void {
            DB::connection($name)->statement('drop schema "'.$schema.'" cascade');
            DB::purge($name);
        }];
    }

    /**
     * @param  array<string, mixed>  $base
     * @return array{0: string, 1: Closure(): void}
     */
    private static function openMysqlDatabase(array $base, string $name): array
    {
        $database = $name.'_'.Str::lower(Str::random(12));

        // A second connection to the SERVER (via the suite's own database) does the
        // create and the drop: you cannot connect to a database that does not exist.
        $admin = $name.'_admin';
        config()->set('database.connections.'.$admin, $base);
        DB::purge($admin);

        try {
            DB::connection($admin)->statement('create database `'.$database.'`');
        } catch (\Throwable $e) {
            throw new RuntimeException(
                'Could not create a throwaway database on '.($base['driver'] ?? '?').'. The migration rollback check '
                .'needs an empty database of its own, which means the CREATE privilege — the `engines` CI job connects '
                .'as root on MySQL/MariaDB for exactly this reason. Do not skip this check to work around it: '
                .$e->getMessage(),
                previous: $e,
            );
        }

        config()->set('database.connections.'.$name, array_merge($base, ['database' => $database]));
        DB::purge($name);

        return [$name, function () use ($name, $admin, $database): void {
            DB::purge($name);
            DB::connection($admin)->statement('drop database if exists `'.$database.'`');
            DB::purge($admin);
        }];
    }

    /**
     * @return array{0: string, 1: Closure(): void}
     */
    private static function openSqliteFile(string $name): array
    {
        $file = tempnam(sys_get_temp_dir(), 'cbox-id-'.$name).'.sqlite';
        touch($file);

        config()->set('database.connections.'.$name, [
            'driver' => 'sqlite',
            'database' => $file,
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]);

        DB::purge($name);

        return [$name, function () use ($name, $file): void {
            DB::purge($name);
            @unlink($file);
        }];
    }
}
