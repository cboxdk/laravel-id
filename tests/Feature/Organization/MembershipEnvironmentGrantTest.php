<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\Contracts\Projects;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * A membership can be restricted to a SUBSET of the environments its organization owns.
 *
 * This is the account plane's per-member environment grant, moved to where it will still
 * exist once the account plane is folded away. Three authorization gates read it, so the
 * tests that matter are the ones about what it REFUSES, not what it permits.
 */
function grantRoot(): Environment
{
    return Environment::query()->create([
        'name' => 'Platform',
        'slug' => 'platform-'.Str::ulid(),
        'type' => EnvironmentType::Production,
        'status' => EnvironmentStatus::Active,
        'is_default' => true,
        'settings' => [],
    ]);
}

/**
 * An organization that owns two environments, through a project it owns.
 *
 * @return array{organization: string, user: string, first: string, second: string}
 */
function organizationWithTwoEnvironments(string $name = 'Acme'): array
{
    return app(PlatformRoot::class)->run(function () use ($name): array {
        $organization = app(Organizations::class)->create(new NewOrganization($name, Str::slug($name).'-'.Str::lower((string) Str::ulid())));
        $project = app(Projects::class)->createForOrganization($organization->id, $name);

        $ids = [];

        foreach (['First', 'Second'] as $environmentName) {
            $ids[] = Environment::query()->create([
                'name' => $environmentName,
                'slug' => Str::slug($name.'-'.$environmentName).'-'.Str::lower((string) Str::ulid()),
                'type' => EnvironmentType::Production,
                'status' => EnvironmentStatus::Active,
                'is_default' => false,
                'project_id' => $project->id,
                'settings' => [],
            ])->id;
        }

        $userId = strtolower((string) Str::ulid());
        app(Memberships::class)->add($organization->id, $userId, MembershipRole::Developer);

        return ['organization' => $organization->id, 'user' => $userId, 'first' => $ids[0], 'second' => $ids[1]];
    });
}

beforeEach(fn () => grantRoot());

it('gives an unrestricted membership every environment its organization owns', function (): void {
    ['organization' => $organization, 'user' => $user, 'first' => $first, 'second' => $second] = organizationWithTwoEnvironments();

    // The default, and it has to be the permissive one: false would mean "restricted to
    // the empty set", so a deployment that migrated and had not yet been re-pointed would
    // lock every member out of every environment on the next request.
    $reachable = app(PlatformRoot::class)->run(
        fn (): array => app(Memberships::class)->accessibleEnvironmentIds($organization, $user),
    );

    expect($reachable)->toHaveCount(2)
        ->and($reachable)->toContain($first)
        ->and($reachable)->toContain($second);
});

it('narrows a membership to the environments it was granted', function (): void {
    ['organization' => $organization, 'user' => $user, 'first' => $first, 'second' => $second] = organizationWithTwoEnvironments();

    app(PlatformRoot::class)->run(function () use ($organization, $user, $first): void {
        app(Memberships::class)->setEnvironmentAccess($organization, $user, all: false, environmentIds: [$first]);
    });

    $reachable = app(PlatformRoot::class)->run(
        fn (): array => app(Memberships::class)->accessibleEnvironmentIds($organization, $user),
    );

    expect($reachable)->toBe([$first])
        ->and($reachable)->not->toContain($second);
})->group('security');

it('refuses to grant an environment another organization owns', function (): void {
    ['organization' => $organization, 'user' => $user, 'first' => $first] = organizationWithTwoEnvironments('Acme');
    ['first' => $someoneElses] = organizationWithTwoEnvironments('Other');

    app(PlatformRoot::class)->run(function () use ($organization, $user, $first, $someoneElses): void {
        app(Memberships::class)->setEnvironmentAccess($organization, $user, all: false, environmentIds: [$first, $someoneElses]);
    });

    $reachable = app(PlatformRoot::class)->run(
        fn (): array => app(Memberships::class)->accessibleEnvironmentIds($organization, $user),
    );

    expect($reachable)->toBe([$first])
        ->and($reachable)->not->toContain($someoneElses);

    // AND THE ROW WAS NEVER WRITTEN, which is a different claim from the one above and
    // needs its own assertion. The read intersects with current ownership too, so deleting
    // the write-side filter leaves every answer here unchanged — I removed it and all six
    // tests stayed green. Two filters, one observable outcome: the second is real defence
    // in depth, and defence nothing can see is defence nobody will keep.
    //
    // A stored grant naming another organization's environment is a live liability even
    // while the read filters it out: it becomes access the moment that environment moves
    // INTO this organization, which is an ordinary administrative act nobody would connect
    // to a member's grant list.
    $stored = app(PlatformRoot::class)->run(
        fn (): array => app(Memberships::class)->of($organization, $user)?->environments()->pluck('environments.id')->all() ?? [],
    );

    expect($stored)->toBe([$first]);
})->group('security');

it('drops the grants when the restriction is lifted', function (): void {
    ['organization' => $organization, 'user' => $user, 'first' => $first] = organizationWithTwoEnvironments();
    $memberships = app(Memberships::class);

    app(PlatformRoot::class)->run(function () use ($memberships, $organization, $user, $first): void {
        $memberships->setEnvironmentAccess($organization, $user, all: false, environmentIds: [$first]);
        $memberships->setEnvironmentAccess($organization, $user, all: true);
    });

    // Both halves, because the point is that they cannot disagree. A boolean saying
    // "everything" beside rows saying "this one" is a question with two answers, and the
    // readers would have to pick between them — and would pick differently.
    $reachable = app(PlatformRoot::class)->run(
        fn (): array => $memberships->accessibleEnvironmentIds($organization, $user),
    );

    expect($reachable)->toHaveCount(2)
        ->and(app(PlatformRoot::class)->run(
            fn (): int => $memberships->of($organization, $user)?->environments()->count() ?? -1,
        ))->toBe(0);
})->group('security');

it('answers nothing for a subject with no membership', function (): void {
    ['organization' => $organization] = organizationWithTwoEnvironments();

    // Empty rather than null, and never the unrestricted set. Every reader of this is an
    // authorization gate, so "unknown" and "unrestricted" must not be the same value.
    $reachable = app(PlatformRoot::class)->run(
        fn (): array => app(Memberships::class)->accessibleEnvironmentIds($organization, strtolower((string) Str::ulid())),
    );

    expect($reachable)->toBe([]);
})->group('security');

it('stops answering yes when a granted environment leaves the organization', function (): void {
    ['organization' => $organization, 'user' => $user, 'first' => $first] = organizationWithTwoEnvironments();
    ['organization' => $elsewhere] = organizationWithTwoEnvironments('Other');

    app(PlatformRoot::class)->run(function () use ($organization, $user, $first, $elsewhere): void {
        app(Memberships::class)->setEnvironmentAccess($organization, $user, all: false, environmentIds: [$first]);

        // The environment moves house. The grant row survives it — nothing cascades on a
        // project changing owner — and the row alone would still say yes.
        $project = app(Projects::class)->createForOrganization($elsewhere, 'Moved');
        Environment::query()->whereKey($first)->update(['project_id' => $project->id]);
    });

    $reachable = app(PlatformRoot::class)->run(
        fn (): array => app(Memberships::class)->accessibleEnvironmentIds($organization, $user),
    );

    // Ownership is the fact; the grant only narrows it. Intersecting on READ as well as on
    // write is what keeps a stale row from outliving the ownership it was granted under.
    expect($reachable)->toBe([]);
})->group('security');

it('carries an existing account-plane restriction onto the membership', function (): void {
    // The state every live deployment is in: the restriction is on the account member, and
    // the membership beside it has never heard of it. Nothing above exercises this path —
    // those tests write memberships directly — so the migration's backfill would ship
    // unverified, and a backfill nothing runs is how a restriction silently becomes
    // unrestricted access.
    $result = app(AccountProvisioner::class)->provision(
        new AccountBlueprint('Acme', 'owner@acme.test', 'Owner', 'a-strong-unbreached-passphrase'),
    );

    $organizationId = (string) $result->account->organization_id;
    $subjectId = (string) $result->member->refresh()->subject_id;

    $environmentId = app(PlatformRoot::class)->run(function () use ($organizationId): string {
        $project = app(Projects::class)->createForOrganization($organizationId, 'Owned');

        return (string) Environment::query()->create([
            'name' => 'Staging',
            'slug' => 'staging-'.Str::lower((string) Str::ulid()),
            'type' => EnvironmentType::Production,
            'status' => EnvironmentStatus::Active,
            'is_default' => false,
            'project_id' => $project->id,
            'settings' => [],
        ])->id;
    });

    DB::table('account_members')->where('id', $result->member->id)->update(['all_environments' => false]);
    DB::table('account_member_environments')->insert([
        'account_member_id' => $result->member->id,
        'environment_id' => $environmentId,
    ]);

    // The membership starts unrestricted — which is the default, and the reason the
    // backfill has to run: leaving it there turns a restricted member into an
    // unrestricted one the moment the readers are re-pointed.
    expect(app(PlatformRoot::class)->run(
        fn (): bool => app(Memberships::class)->of($organizationId, $subjectId)?->all_environments ?? false,
    ))->toBeTrue();

    /** @var object{up: callable} $migration */
    $migration = require dirname(__DIR__, 3).'/database/migrations/2026_08_08_000100_give_a_membership_its_environment_grants.php';
    $migration->up();

    expect(app(PlatformRoot::class)->run(
        fn (): array => app(Memberships::class)->accessibleEnvironmentIds($organizationId, $subjectId),
    ))->toBe([$environmentId]);
})->group('security');
