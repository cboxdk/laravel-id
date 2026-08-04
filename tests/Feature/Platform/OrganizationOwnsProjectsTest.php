<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\Contracts\OrganizationProjects;
use Cbox\Id\Platform\Models\Project;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Cbox\Id\Platform\ValueObjects\ProvisionedAccount;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * An account IS an organization in the platform root, so an organization can own IdP
 * products directly — the bridge that lets a host read ownership from the organization
 * side without going through the account plane. `Account::projects()` is untouched and
 * keeps answering the same thing.
 */

/**
 * The platform root — "tenant 1", where accounts are homed as organizations.
 *
 * Named apart from the identical helper in AccountMemberSubjectTest: Pest requires
 * every test file into one process, so two functions of one name is a fatal error that
 * takes the whole run with it, not a failure in one file.
 */
function rootForOwnedProjects(): Environment
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

function provisionOwningAccount(string $name, string $email): ProvisionedAccount
{
    return app(AccountProvisioner::class)->provision(new AccountBlueprint(
        accountName: $name,
        ownerEmail: $email,
        ownerName: 'Owner',
        ownerPassword: 'a-strong-unbreached-passphrase',
        environmentLimit: 3,
    ));
}

it('gives the account\'s organization the same projects the account has', function (): void {
    $root = rootForOwnedProjects();
    $result = provisionOwningAccount('Acme', 'owner@acme.test');

    $organizationId = $result->account->refresh()->organization_id;
    expect($organizationId)->not->toBeNull()
        // The link is stamped on the project itself, not inferred at read time.
        ->and($result->project->refresh()->organization_id)->toBe($organizationId);

    // Read from the organization side, inside the root environment — the only place
    // the organization row is reachable at all.
    $this->runAsEnvironment($root, function () use ($organizationId, $result): void {
        $organization = Organization::query()->findOrFail($organizationId);

        expect($organization->projects->pluck('id')->all())->toBe([$result->project->id])
            // …and the account-side answer is byte-for-byte the same set. Both halves
            // of the bridge report the same ownership; neither is now authoritative
            // over the other.
            ->and($result->account->projects->pluck('id')->all())
            ->toBe($organization->projects->pluck('id')->all());
    });
});

it('reaches the organization\'s environments through its projects', function (): void {
    $root = rootForOwnedProjects();
    $result = provisionOwningAccount('Acme', 'owner@acme.test');
    $staging = app(AccountProvisioner::class)->addEnvironment($result->project, 'Staging');

    // A second, separately-billed product under the same organization.
    $second = app(AccountProvisioner::class)->addProject($result->account, 'Product Two');
    $secondEnvironment = app(AccountProvisioner::class)->addEnvironment($second, 'Production');

    $organizationId = $result->account->refresh()->organization_id;

    $this->runAsEnvironment($root, function () use ($organizationId, $result, $staging, $secondEnvironment): void {
        $organization = Organization::query()->findOrFail($organizationId);

        // Every stage of every product, across projects — the has-many-through, not a
        // denormalized column.
        expect($organization->environments->pluck('id')->sort()->values()->all())
            ->toBe(collect([$result->environment->id, $staging->id, $secondEnvironment->id])->sort()->values()->all());
    });
});

it('never shows one organization another\'s projects', function (): void {
    $root = rootForOwnedProjects();
    $acme = provisionOwningAccount('Acme', 'owner@acme.test');
    $globex = provisionOwningAccount('Globex', 'owner@globex.test');

    $acmeOrganization = $acme->account->refresh()->organization_id;
    $globexOrganization = $globex->account->refresh()->organization_id;

    expect($acmeOrganization)->not->toBe($globexOrganization);

    $this->runAsEnvironment($root, function () use ($acmeOrganization, $acme, $globex): void {
        $organization = Organization::query()->findOrFail($acmeOrganization);

        expect($organization->projects->pluck('id')->all())->toBe([$acme->project->id])
            ->and($organization->projects->pluck('id')->all())->not->toContain($globex->project->id)
            ->and($organization->environments->pluck('id')->all())->not->toContain($globex->environment->id);
    });
});

/**
 * @group isolation
 *
 * The relation crosses out of the environment scope by design — a project owns
 * environments and cannot be inside one. What keeps that safe is the PARENT: the
 * organization is environment-owned, so it cannot be loaded from another environment,
 * and an unreachable parent has no reachable children.
 */
it('cannot be reached from another environment, because the organization cannot be', function (): void {
    rootForOwnedProjects();
    $result = provisionOwningAccount('Acme', 'owner@acme.test');
    $organizationId = $result->account->refresh()->organization_id;

    // The account's OWN environment is a tenant plane, not the root. From there the
    // organization is invisible even by primary key.
    $this->runAsEnvironment($result->environment, function () use ($organizationId): void {
        expect(Organization::query()->find($organizationId))->toBeNull()
            ->and(Organization::query()->count())->toBe(0);
    });

    // And with no environment in context at all, deny-by-default holds.
    $this->forgetEnvironment();
    expect(Organization::query()->find($organizationId))->toBeNull();
})->group('isolation');

it('stamps the owning organization on any project create, not just the provisioner\'s', function (): void {
    rootForOwnedProjects();
    $result = provisionOwningAccount('Acme', 'owner@acme.test');
    $organizationId = $result->account->refresh()->organization_id;

    // A host reaching for the model directly still gets the link — otherwise this
    // project would be healthy from the account side and invisible from the
    // organization side, a one-directional split of the same fact.
    $direct = Project::query()->create([
        'account_id' => $result->account->id,
        'name' => 'Straight To The Model',
        'slug' => 'straight-to-the-model',
    ]);

    expect($direct->organization_id)->toBe($organizationId);
});

it('leaves the organization null when the account was never homed', function (): void {
    // No platform root: provisioning cannot home the account, so its project has no
    // organization either. "No owner" must stay null rather than borrow one.
    Environment::query()->where('is_default', true)->update(['is_default' => false]);

    $result = provisionOwningAccount('Bootstrap', 'owner@bootstrap.test');

    expect($result->account->refresh()->organization_id)->toBeNull()
        ->and($result->project->refresh()->organization_id)->toBeNull();
});

it('refuses two projects with the same handle under one organization', function (): void {
    rootForOwnedProjects();
    $acme = provisionOwningAccount('Acme', 'owner@acme.test');
    $other = provisionOwningAccount('Other', 'owner@other.test');

    $organizationId = $acme->account->refresh()->organization_id;

    // Deliberately from a DIFFERENT account, so the pre-existing (account_id, slug)
    // key cannot be what refuses this: only the organization-side uniqueness can.
    expect(fn () => Project::query()->create([
        'account_id' => $other->account->id,
        'organization_id' => $organizationId,
        'name' => 'Acme',
        'slug' => $acme->project->slug,
    ]))->toThrow(QueryException::class);
});

it('answers ownership by organization id, and refuses an unowned project', function (): void {
    rootForOwnedProjects();
    $acme = provisionOwningAccount('Acme', 'owner@acme.test');
    $globex = provisionOwningAccount('Globex', 'owner@globex.test');

    $acmeOrganization = $acme->account->refresh()->organization_id;
    $globexOrganization = $globex->account->refresh()->organization_id;

    // A project belonging to nobody on this side of the bridge (an account that
    // predates homing).
    $unowned = Project::query()->create([
        'account_id' => $acme->account->id,
        'organization_id' => null,
        'name' => 'Legacy',
        'slug' => 'legacy',
    ]);
    $unowned->forceFill(['organization_id' => null])->save();

    $projects = app(OrganizationProjects::class);

    expect($projects->ownedByOrganization($acme->project->id, $acmeOrganization))->toBeTrue()
        // Another organization's product is not yours…
        ->and($projects->ownedByOrganization($globex->project->id, $acmeOrganization))->toBeFalse()
        // …and neither is one with no owner at all.
        ->and($projects->ownedByOrganization($unowned->id, $acmeOrganization))->toBeFalse()
        ->and($projects->forOrganization($acmeOrganization)->pluck('id')->all())->toBe([$acme->project->id])
        ->and($projects->forOrganization($globexOrganization)->pluck('id')->all())->toBe([$globex->project->id]);
});
