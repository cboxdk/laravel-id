<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\Contracts\Projects;
use Cbox\Id\Platform\Models\Project;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * An organization can own an IdP product ALONE — no account row behind it.
 *
 * `2026_08_06_000100` gave `projects` an `organization_id` and said in as many words that
 * dropping the account requirement was a separate, subtractive step; `2026_08_07_000100`
 * is that step, and this is what makes it more than a schema change. A nullable column
 * with no statement in the codebase able to leave it empty is a capability nobody has.
 *
 * These are the tests that would have failed while `account_id` was NOT NULL — which is
 * the only honest way to assert a constraint was removed: exercise the thing it forbade.
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

it('creates a project an organization owns with no account', function (): void {
    $organizationId = strtolower((string) Str::ulid());

    $project = app(Projects::class)->createForOrganization($organizationId, 'Standalone');

    // NULL, not ''. The column is nullable and NULL is what "no account owns this" means;
    // an empty string satisfies the column, fails the foreign key on an engine that checks
    // it, and reads as an account id to every comparison written without a null check.
    expect($project->account_id)->toBeNull()
        ->and($project->organization_id)->toBe($organizationId)
        ->and($project->slug)->toBe('standalone');
});

it('finds it from the organization side', function (): void {
    $organizationId = strtolower((string) Str::ulid());
    app(Projects::class)->createForOrganization($organizationId, 'Standalone');

    $found = app(Projects::class)->forOrganization($organizationId);

    expect($found)->toHaveCount(1)
        ->and($found->first()?->name)->toBe('Standalone')
        // …and the ownership question answers yes for its owner and no for anyone else,
        // which is the read every authorization check in the console goes through.
        ->and(app(Projects::class)->ownedByOrganization((string) $found->first()?->id, $organizationId))->toBeTrue()
        ->and(app(Projects::class)->ownedByOrganization((string) $found->first()?->id, strtolower((string) Str::ulid())))->toBeFalse();
});

it('makes the second project of one name unique within the organization', function (): void {
    $organizationId = strtolower((string) Str::ulid());
    $projects = app(Projects::class);

    $projects->createForOrganization($organizationId, 'Default');
    $second = $projects->createForOrganization($organizationId, 'Default');

    // The account path scopes its slug loop to `(account_id, slug)`; this path has no
    // account, so scoping to the same column would find nothing, hand back 'default'
    // twice and violate the `(organization_id, slug)` key that 2026_08_06_000100 added —
    // surfacing as a database error on an ordinary "create a second project called
    // Default". Hence `uniqueSlug()` taking the column it scopes to.
    expect($second->slug)->toBe('default-2');
});

it('lets two organizations each have a default', function (): void {
    $projects = app(Projects::class);
    $first = strtolower((string) Str::ulid());
    $second = strtolower((string) Str::ulid());

    $projects->createForOrganization($first, 'Default');
    $other = $projects->createForOrganization($second, 'Default');

    // The other half of the same rule, and the one a too-eager global unique index breaks.
    expect($other->slug)->toBe('default');
});

it('leaves an account-owned project owned by its account', function (): void {
    $result = app(AccountProvisioner::class)->provision(
        new AccountBlueprint('Acme', 'owner@acme.test', 'Owner', 'a-strong-unbreached-passphrase'),
    );

    $project = app(Projects::class)->forAccount($result->account->id)->firstOrFail();

    // Nothing was rewritten. The constraint was lifted, not the relationship — a reader
    // that has always gone through `forAccount()` sees exactly what it saw before, and
    // `Project::booted()` still derives the organization from the account.
    expect($project->account_id)->toBe($result->account->id)
        ->and($project->organization_id)->toBe($result->account->organization_id);
});

it('homes a project whose account was homed after the fact', function (): void {
    $result = app(AccountProvisioner::class)->provision(
        new AccountBlueprint('Acme', 'owner@acme.test', 'Owner', 'a-strong-unbreached-passphrase'),
    );

    // The state a deployment that ran 2026_08_05_000200 late is in: the account has an
    // organization, its project does not, because the project predates the backfill.
    DB::table('projects')->where('account_id', $result->account->id)->update(['organization_id' => null]);

    /** @var object{up: callable} $migration */
    $migration = require dirname(__DIR__, 3).'/database/migrations/2026_08_07_000100_let_a_project_outlive_its_account.php';
    $migration->up();

    // Repaired, not refused. Refusing would leave the deployment unable to migrate with no
    // action it could take that the migration could not take for it — the source is the
    // account row, which is right there.
    expect(Project::query()->where('account_id', $result->account->id)->value('organization_id'))
        ->toBe($result->account->organization_id);
});
