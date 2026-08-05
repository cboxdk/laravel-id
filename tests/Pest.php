<?php

declare(strict_types=1);
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Models\Project;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Tests\Support\ExternalDriverTestCase;
use Cbox\Id\Tests\Support\MigrationTestCase;
use Cbox\Id\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(TestCase::class)->in('Feature');

// Bring-your-own-RBAC tests boot under the external access-control driver, so they
// use a base case that selects it before the providers register. Kept in its own
// top-level folder because Pest forbids two different base cases on one file, and a
// nested folder would still be claimed by the blanket binding above.
uses(ExternalDriverTestCase::class)->in('External');

// The migration rollback check is a top-level folder rather than a Feature test so it
// escapes the RefreshDatabase binding below: it brings its OWN empty database, and a
// `migrate:fresh` of the suite's would be minutes of pointless DDL on a server engine.
// Its base case also leaves the suite's connection entirely untouched — see the class.
uses(MigrationTestCase::class)->in('Migrations');

// On a SERVER engine, migrate once per process and wrap each test in a transaction.
//
// Testbench's default is to migrate and roll back around EVERY test. Against sqlite
// `:memory:` that is the only correct option (the database lives in the connection,
// so it cannot outlive one) and it is cheap. Against MySQL or PostgreSQL it is not:
// this package ships ~390 DDL statements, and a real engine takes seconds over each
// create-and-drop pass — measured at over a minute per test on MySQL 8.4, which puts
// a full run in the hours and would make the CI job that guards MySQL support the
// first thing anyone disables.
//
// This is why the trait is applied HERE and conditionally rather than in TestCase:
// the sqlite run — the default, and the one the whole 1357-test baseline was
// established on — keeps byte-identical behaviour, and only the server-engine job
// takes the transactional path.
//
// The cost is that `migrate:fresh` wipes tables rather than calling down(), so the
// rollback path is not exercised here at all. CBOX_ID_TEST_MIGRATE_EACH=1 opts back
// out for a single file, which is how CI still runs the migrator itself on a server
// engine — see the "Migrations up" step in .github/workflows/ci.yml. down() is proved
// separately and explicitly by tests/Migrations/MigrationRollbackTest.php, which is
// why that file is not under Feature/.
if (in_array(getenv('DB_CONNECTION'), ['mysql', 'mariadb', 'pgsql'], true)
    && getenv('CBOX_ID_TEST_MIGRATE_EACH') !== '1') {
    uses(RefreshDatabase::class)->in('Feature');
    uses(RefreshDatabase::class)->in('External');
}

/**
 * Suspend / reactivate the CUSTOMER that owns an environment.
 *
 * Ownership runs environment → project → organization. It used to be a column on the
 * environment (`account_id`), which made this a one-liner; the column was a denormalized
 * copy of the same fact, and a copy of ownership is a second place for ownership to be
 * wrong.
 *
 * Inside the platform root, because `organizations` is environment-owned and these tests
 * stand on a tenant host by design — the thing they are testing is what that host serves.
 */
function ownerOrganizationOf(Environment $environment): string
{
    $projectId = $environment->refresh()->project_id;

    expect($projectId)->not->toBeNull('the environment has no project, so it has no owner to suspend');

    $organizationId = app(PlatformRoot::class)->run(
        fn (): mixed => Project::query()->whereKey($projectId)->value('organization_id'),
    );

    expect($organizationId)->toBeString();

    return (string) $organizationId;
}

function suspendOwnerOf(Environment $environment): void
{
    $id = ownerOrganizationOf($environment);

    app(PlatformRoot::class)->run(fn () => app(Organizations::class)->suspend($id, 'op_test'));
}

function reactivateOwnerOf(Environment $environment): void
{
    $id = ownerOrganizationOf($environment);

    app(PlatformRoot::class)->run(fn () => app(Organizations::class)->reactivate($id, 'op_test'));
}

/**
 * The platform-root environment ("tenant 1") — where the platform's own people and its
 * customers' organizations live. Idempotent: a deployment has exactly one, and so does a
 * test.
 *
 * Provisioning without one used to be allowed and produced a half-born customer: an
 * organization that was never created, an owner with nowhere to be a member. Every caller
 * downstream then carried a null check for a state only a broken install could reach.
 * {@see TenantProvisioner::provision()} refuses now, so a fixture that skips this gets a
 * clear failure instead of a customer that half exists.
 */
function platformRootEnvironment(): Environment
{
    $existing = Environment::query()->where('is_default', true)->first();

    if ($existing !== null) {
        return $existing;
    }

    return Environment::query()->create([
        'name' => 'Platform',
        'slug' => 'platform-root-'.Str::lower((string) Str::ulid()),
        'type' => EnvironmentType::Production,
        'status' => EnvironmentStatus::Active,
        'is_default' => true,
        'settings' => [],
    ]);
}
