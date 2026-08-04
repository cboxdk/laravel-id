<?php

declare(strict_types=1);

use Cbox\Id\Tests\Support\ThrowawayDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

/**
 * The schema half of a migration is loud when it fails; the BACKFILL half is silent.
 *
 * `let_an_organization_own_projects` adds a column and then fills it from
 * `accounts.organization_id`. If that loop were dropped, every existing customer's
 * products would still be perfectly readable from the account side and simply absent
 * from the organization side — the exact asymmetry the column exists to remove, and
 * one no schema assertion catches. So this builds the tables it touches, puts rows in
 * them in the shape a live deployment carries, and then runs the migration.
 *
 * It lives outside tests/Feature because it brings its own empty database (see
 * {@see ThrowawayDatabase}) and has no use for the suite's.
 */

/**
 * The migrations that build the three tables involved, by FILE — not every path a real
 * install ends up with.
 *
 * The sibling rollback test is the one that must migrate everything, and it does so
 * three times over in this same PHP process; a fourth full-schema build there tips the
 * run over its memory limit. Nothing here needs the other ~85 tables, and naming the
 * files explicitly means a rename fails loudly rather than silently narrowing the
 * proof. These are still the REAL migrations, applied in the real order.
 *
 * @return list<string>
 */
function backfillPriorMigrations(): array
{
    $directory = dirname(__DIR__, 2).'/database/migrations';

    return [
        $directory.'/2026_01_01_000600_create_organization_tables.php',
        $directory.'/2026_07_17_000100_create_accounts_table.php',
        $directory.'/2026_07_19_000100_create_projects_table.php',
        $directory.'/2026_07_25_000400_add_organization_to_accounts.php',
    ];
}

function backfillMigrationUnderTest(): string
{
    return dirname(__DIR__, 2).'/database/migrations/2026_08_06_000100_let_an_organization_own_projects.php';
}

/**
 * Run an artisan command, fetching its (potentially large) output only when it is about
 * to be reported. `Artisan::output()` inlined into an assertion message is evaluated on
 * the success path too, and buffering a schema build's whole output is not free in a
 * process already close to its limit.
 *
 * @param  array<string, mixed>  $options
 */
function migrateOrFail(string $command, array $options, string $context): void
{
    $exit = Artisan::call($command, $options);

    expect($exit)->toBe(0, $exit === 0 ? '' : $context.': '.Artisan::output());
}

it('backfills the owning organization onto the projects of every homed account', function (): void {
    [$connection, $cleanup] = ThrowawayDatabase::open('org-projects');

    try {
        $base = [
            '--database' => $connection,
            '--realpath' => true,
            '--force' => true,
        ];

        migrateOrFail('migrate', $base + ['--path' => backfillPriorMigrations()], 'the prior migrations failed');

        // Sanity: this really is the pre-migration shape. Without it, a column that
        // somehow already existed and was already filled would make everything below
        // pass for the worst possible reason.
        expect(Schema::connection($connection)->hasColumn('projects', 'organization_id'))
            ->toBeFalse('the column already existed, so nothing below proves the backfill ran');

        $organizationId = (string) Str::ulid();
        $homedAccount = (string) Str::ulid();
        $unhomedAccount = (string) Str::ulid();
        $homedProject = (string) Str::ulid();
        $unhomedProject = (string) Str::ulid();

        DB::connection($connection)->table('organizations')->insert([
            'id' => $organizationId,
            'environment_id' => (string) Str::ulid(),
            'name' => 'Acme',
            'slug' => 'acme',
            'type' => 'customer',
            'status' => 'active',
            'settings' => '{}',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::connection($connection)->table('accounts')->insert([
            [
                'id' => $homedAccount,
                'organization_id' => $organizationId,
                'name' => 'Acme',
                'status' => 'active',
                'environment_limit' => 2,
                'settings' => '{}',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                // Provisioned before the unified-identity cutover: no organization.
                'id' => $unhomedAccount,
                'organization_id' => null,
                'name' => 'Legacy',
                'status' => 'active',
                'environment_limit' => 2,
                'settings' => '{}',
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);

        DB::connection($connection)->table('projects')->insert([
            [
                'id' => $homedProject,
                'account_id' => $homedAccount,
                'name' => 'Default',
                'slug' => 'default',
                'status' => 'active',
                'environment_limit' => 2,
                'settings' => '{}',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'id' => $unhomedProject,
                'account_id' => $unhomedAccount,
                // The same handle under a different account — legal before this
                // migration, and it must stay legal after. It does, precisely because
                // the new key is on the ORGANIZATION and this project has none.
                'name' => 'Default',
                'slug' => 'default',
                'status' => 'active',
                'environment_limit' => 2,
                'settings' => '{}',
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);

        migrateOrFail(
            'migrate',
            $base + ['--path' => [backfillMigrationUnderTest()]],
            'the migration failed on a database with existing accounts',
        );

        $projects = DB::connection($connection)->table('projects');

        expect($projects->where('id', $homedProject)->value('organization_id'))
            ->toBe($organizationId, 'a homed account\'s project was left without its organization')
            // An account with no home has nothing to inherit, and must not borrow one.
            ->and($projects->where('id', $unhomedProject)->value('organization_id'))
            ->toBeNull('an unhomed account\'s project was given an organization it does not have');
    } finally {
        $cleanup();
    }
})->group('migrations-rollback');
