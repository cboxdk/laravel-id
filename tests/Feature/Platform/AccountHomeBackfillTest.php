<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\PlatformRoot;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * The state no fixture can reach on its own.
 *
 * `accounts.organization_id` is written in exactly two places, both at CREATION time,
 * and every fixture in both suites builds its account through
 * {@see AccountProvisioner::provision()} — which homes it on the way past. So the one
 * state a real deployment is actually in, an account created before the column existed,
 * is the one state nothing here could produce, and the console area that depends on it
 * broke without a single red test.
 *
 * The rows are INSERTED, not provisioned-then-damaged. Un-homing a healthy account would
 * be a reconstruction of the state rather than the state itself, and it would have to
 * guess which of the organization's rows to take back out. A legacy account was never
 * homed in the first place, so the honest fixture is the bare row — which is also why
 * these cost the suite nothing: `provision()` stands up an environment and generates its
 * signing keys, and five of those is what put this process over its memory limit.
 *
 * Runs the migration's `up()` directly rather than reversing the schema on a throwaway
 * database. The half that can silently go missing here is the LOOP, not the DDL — there
 * is no DDL — so the cheap test is the complete one.
 */
function homeBackfill(): object
{
    /** @var object{up: callable} $migration */
    $migration = require dirname(__DIR__, 3).'/database/migrations/2026_08_05_000200_home_every_account_that_predates_its_organization.php';

    return $migration;
}

/** An account as it exists on a deployment that predates the column: no organization. */
function legacyAccount(string $name): string
{
    $id = strtolower((string) Str::ulid());

    DB::table('accounts')->insert([
        'id' => $id,
        'organization_id' => null,
        'name' => $name,
        'status' => 'active',
        'environment_limit' => 2,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    return $id;
}

function homeOf(string $accountId): ?string
{
    $value = DB::table('accounts')->where('id', $accountId)->value('organization_id');

    return is_string($value) ? $value : null;
}

/**
 * Every one of these needs a platform root to exist: the backfill skips a deployment
 * without one — correctly, since there is nowhere to home an account INTO — so a test
 * missing it would pass while asserting nothing.
 */
beforeEach(function (): void {
    Environment::query()->create([
        'name' => 'Platform',
        'slug' => 'platform-'.Str::ulid(),
        'type' => EnvironmentType::Production,
        'status' => EnvironmentStatus::Active,
        'is_default' => true,
        'settings' => [],
    ]);
});

it('homes an account that predates the column', function (): void {
    $accountId = legacyAccount('Acme');

    expect(homeOf($accountId))->toBeNull();

    homeBackfill()->up();

    $organizationId = homeOf($accountId);

    expect($organizationId)->toBeString()->not->toBe('');

    $organization = app(PlatformRoot::class)->run(
        fn (): ?Organization => Organization::query()->whereKey($organizationId)->first(),
    );

    expect($organization)->not->toBeNull()
        ->and($organization->name)->toBe('Acme')
        ->and($organization->slug)->toBe('acme');

    // The depth-0 self-row. Without it the organization is invisible to its own
    // descendant query — childless is a different thing from absent, and only one of
    // them is what a fresh organization should be.
    expect(DB::table('organization_closure')
        ->where('ancestor_id', $organizationId)
        ->where('descendant_id', $organizationId)
        ->where('depth', 0)
        ->exists())->toBeTrue();
});

it('lands in the platform root, not the ambient environment', function (): void {
    $accountId = legacyAccount('Acme');

    homeBackfill()->up();

    $root = DB::table('environments')->where('is_default', true)->value('id');

    // Organizations are environment-owned and the tenancy kernel is deny-by-default, so
    // one written into the wrong environment is not merely misfiled — every account-plane
    // read of it returns empty, which reads as "no such account" rather than as an error.
    expect(DB::table('organizations')->where('id', homeOf($accountId))->value('environment_id'))
        ->toBe($root);
});

it('gives two accounts of the same name distinct slugs', function (): void {
    $first = legacyAccount('Acme');
    $second = legacyAccount('Acme');

    homeBackfill()->up();

    // The reservation has to be held IN THE LOOP. Re-querying per account — which is what
    // the provisioner does, correctly, because it creates one at a time — would not see
    // the slug the previous iteration just took, and the second insert would hit the
    // (environment_id, slug) unique key half way through the backfill.
    $slugs = DB::table('organizations')
        ->whereIn('id', [homeOf($first), homeOf($second)])
        ->pluck('slug')
        ->all();

    expect($slugs)->toHaveCount(2)
        ->and(array_unique($slugs))->toHaveCount(2);
});

it('does not collide with an organization the platform root already has', function (): void {
    app(PlatformRoot::class)->run(function (): void {
        Organization::query()->create(['name' => 'Acme', 'slug' => 'acme', 'settings' => []]);
    });

    $accountId = legacyAccount('Acme');

    homeBackfill()->up();

    expect(DB::table('organizations')->where('id', homeOf($accountId))->value('slug'))->toBe('acme-2');
});

it('changes nothing on a second run', function (): void {
    $accountId = legacyAccount('Acme');

    homeBackfill()->up();

    $organizationId = homeOf($accountId);
    $organizations = DB::table('organizations')->count();

    homeBackfill()->up();

    expect(homeOf($accountId))->toBe($organizationId)
        ->and(DB::table('organizations')->count())->toBe($organizations);
});

it('leaves an already-homed account alone', function (): void {
    $accountId = legacyAccount('Acme');

    homeBackfill()->up();

    $organizationId = homeOf($accountId);
    $organizations = DB::table('organizations')->count();

    homeBackfill()->up();

    expect(homeOf($accountId))->toBe($organizationId)
        ->and(DB::table('organizations')->count())->toBe($organizations);
});

it('does nothing at all on a deployment with no platform root', function (): void {
    DB::table('environments')->update(['is_default' => false]);

    $accountId = legacyAccount('Acme');

    homeBackfill()->up();

    // Inventing an environment here would write the platform's own people somewhere no
    // installer chose. `PlatformRoot` degrades the same way rather than guessing.
    expect(homeOf($accountId))->toBeNull()
        ->and(DB::table('organizations')->count())->toBe(0);
});
