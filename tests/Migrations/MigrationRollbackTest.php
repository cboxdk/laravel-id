<?php

declare(strict_types=1);

use Cbox\Id\Tests\Support\ThrowawayDatabase;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

/**
 * `down()` has to work, and until this test existed nothing proved it did.
 *
 * The `engines` CI job used to carry a step captioned "migrations up and down". It
 * ran the suite under Testbench's default strategy, whose rollback is `--path`-scoped
 * to the ONE publishable migration the TestCase loads directly — so it reversed that
 * file and nothing else. Measured against an empty PostgreSQL, 83 tables and 90 rows
 * in `migrations` survived the "rollback", on every engine, on every release.
 *
 * The half that matters is not the rollback, it is the ASSERTION after it. A rollback
 * step that does not verify emptiness is precisely how this went unnoticed: both
 * `migrate:rollback` and `migrate:reset` exit 0 whether they reversed the whole
 * schema or a single file.
 *
 * It lives OUTSIDE tests/Feature deliberately. tests/Pest.php puts the Feature suite
 * on RefreshDatabase for server engines, and a `migrate:fresh` of the suite's own
 * database is minutes of DDL on MySQL that this test has no use for — it brings its
 * own empty database (see {@see ThrowawayDatabase}).
 *
 * It runs on whatever engine the suite is pointed at. On the default sqlite it is the
 * cheap version every contributor gets — and the strict one, because SQLite rebuilds
 * a table to drop a column and then re-validates every surviving index against the
 * result, which is how four of the five broken `down()` methods surfaced. In CI it
 * also runs against PostgreSQL, MySQL and MariaDB, where drop ORDER against real
 * foreign keys is what gets enforced instead.
 */

/**
 * Every migration path a real install ends up with: the ones the service providers
 * register with the migrator (this package's own, its access-control subdirectory,
 * and its dependencies'), plus the optional users migration a greenfield host
 * publishes.
 *
 * Passed explicitly to both `migrate` and `migrate:reset`, because `--path` REPLACES
 * the registered set rather than adding to it — which is the whole defect: a rollback
 * given one path reverses one path, silently and successfully.
 *
 * @return list<string>
 */
function allMigrationPaths(): array
{
    /** @var Migrator $migrator */
    $migrator = app('migrator');

    $paths = array_merge($migrator->paths(), [dirname(__DIR__, 2).'/database/publishable']);

    // `loadMigrationsFrom(__DIR__.'/../../database/migrations')` registers the path
    // with its `..` segments intact, so the same directory named by two different
    // routes would be migrated twice. Resolve before de-duplicating.
    return array_values(array_unique(array_filter(array_map(
        fn (string $path): string => realpath($path) ?: $path,
        $paths,
    ))));
}

it('migrates every path up, all the way back down, and up again', function (): void {
    [$connection, $cleanup] = ThrowawayDatabase::open('rollback');

    try {
        $paths = allMigrationPaths();

        expect($paths)->not->toBeEmpty()
            // A guard against this test's own worst failure mode: pointing the check
            // at a subset of the paths and calling the result proof.
            ->and($paths)->toContain(dirname(__DIR__, 2).'/database/migrations')
            ->and($paths)->toContain(dirname(__DIR__, 2).'/database/migrations/access-control')
            ->and($paths)->toContain(dirname(__DIR__, 2).'/database/publishable');

        $options = [
            '--database' => $connection,
            '--path' => $paths,
            '--realpath' => true,
            '--force' => true,
        ];

        expect(Artisan::call('migrate', $options))->toBe(0, 'php artisan migrate failed: '.Artisan::output());

        $created = ThrowawayDatabase::tables($connection);
        $applied = DB::connection($connection)->table('migrations')->count();

        // Sanity: the rollback below has to be reversing a real schema, not an empty
        // one. Without this, a `migrate` that quietly did nothing would make the
        // emptiness assertion pass for the worst possible reason.
        expect(count($created))->toBeGreaterThan(50)
            ->and($applied)->toBeGreaterThan(50);

        expect(Artisan::call('migrate:reset', $options))
            ->toBe(0, 'php artisan migrate:reset failed: '.Artisan::output());

        // `migrate:reset` keeps the (now empty) `migrations` ledger itself; every
        // other table has to be gone.
        $remaining = array_values(array_diff(ThrowawayDatabase::tables($connection), ['migrations']));

        expect($remaining)->toBe([], count($remaining).' table(s) survived the rollback: '.implode(', ', $remaining))
            ->and(DB::connection($connection)->table('migrations')->count())
            ->toBe(0, 'the migrations ledger still has rows after a full reset');

        // And the way back out. A `down()` may drop a table but leave an index, a
        // sequence, an enum type or a foreign key behind — not all of which the
        // emptiness check can see on every engine, and every one of which makes the
        // next `migrate` fail with "already exists". That is the state an operator is
        // left in after a rollback under pressure, so it is asserted too.
        expect(Artisan::call('migrate', $options))
            ->toBe(0, 'php artisan migrate failed on a rolled-back database: '.Artisan::output());
    } finally {
        $cleanup();
    }
})->group('migrations-rollback');
