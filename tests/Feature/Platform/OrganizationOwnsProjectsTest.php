<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Platform\Contracts\OrganizationProjects;
use Cbox\Id\Platform\Models\Project;
use Cbox\Id\Platform\TenantProvisioner;
use Cbox\Id\Platform\ValueObjects\ProvisionedTenant;
use Cbox\Id\Platform\ValueObjects\TenantBlueprint;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * An organization owns IdP products, and reaches every environment of every product
 * through them.
 *
 * THIS FILE USED TO TEST A BRIDGE. An account was homed as an organization, each owned the
 * same projects from a different side, and most of these tests asserted the two sides
 * agreed — that `Account::projects()` and `Organization::projects()` returned the same set,
 * that a model hook stamped the organization from the account, that an un-homed account
 * left the organization null. There is one side now, so agreement is not a property any
 * more and those tests went with the plane they compared against.
 *
 * What survives is what was never about the bridge: the has-many-through, the isolation
 * between two customers, the uniqueness rule, and — the one worth keeping most — that none
 * of it is reachable from another environment.
 */
function ownedProjectsRoot(): Environment
{
    return platformRootEnvironment();
}

function provisionOwner(string $name, string $email): ProvisionedTenant
{
    return app(TenantProvisioner::class)->provision(new TenantBlueprint(
        organizationName: $name,
        ownerEmail: $email,
        ownerName: 'Owner',
        ownerPassword: 'a-strong-unbreached-passphrase',
        environmentLimit: 3,
    ));
}

it('gives the organization the products it owns', function (): void {
    $root = ownedProjectsRoot();
    $result = provisionOwner('Acme', 'owner@acme.test');

    // The link is stamped on the project at CREATE, not inferred at read time.
    expect($result->project->refresh()->organization_id)->toBe($result->organization->id);

    // Read from the organization side, inside the root — the only place the organization
    // row is reachable at all.
    $this->runAsEnvironment($root, function () use ($result): void {
        $organization = Organization::query()->findOrFail($result->organization->id);

        expect($organization->projects->pluck('id')->all())->toBe([$result->project->id]);
    });
});

it('reaches the organization\'s environments through its projects', function (): void {
    $root = ownedProjectsRoot();
    $result = provisionOwner('Acme', 'owner@acme.test');
    $provisioner = app(TenantProvisioner::class);

    $staging = $provisioner->addEnvironment($result->project, 'Staging');

    // A second, separately-billed product under the same organization.
    $second = $provisioner->addProject($result->organization, 'Product Two');
    $secondEnvironment = $provisioner->addEnvironment($second, 'Production');

    $this->runAsEnvironment($root, function () use ($result, $staging, $secondEnvironment): void {
        $organization = Organization::query()->findOrFail($result->organization->id);

        // Every stage of every product, across projects — the has-many-through, not a
        // denormalized column. `environments.account_id` was that column, and removing it
        // is what made this relation the only answer rather than a second one.
        expect($organization->environments->pluck('id')->sort()->values()->all())
            ->toBe(collect([$result->environment->id, $staging->id, $secondEnvironment->id])->sort()->values()->all());
    });
});

it('never shows one organization another\'s projects', function (): void {
    $root = ownedProjectsRoot();
    $acme = provisionOwner('Acme', 'owner@acme.test');
    $globex = provisionOwner('Globex', 'owner@globex.test');

    expect($acme->organization->id)->not->toBe($globex->organization->id);

    $this->runAsEnvironment($root, function () use ($acme, $globex): void {
        $organization = Organization::query()->findOrFail($acme->organization->id);

        expect($organization->projects->pluck('id')->all())->toBe([$acme->project->id])
            ->and($organization->projects->pluck('id')->all())->not->toContain($globex->project->id)
            ->and($organization->environments->pluck('id')->all())->not->toContain($globex->environment->id);
    });
})->group('security');

/**
 * The relation crosses out of the environment scope by design — a project owns environments
 * and cannot be inside one. What keeps that safe is the PARENT: the organization is
 * environment-owned, so it cannot be loaded from another environment, and an unreachable
 * parent has no reachable children.
 */
it('cannot be reached from another environment, because the organization cannot be', function (): void {
    ownedProjectsRoot();
    $result = provisionOwner('Acme', 'owner@acme.test');
    $organizationId = $result->organization->id;

    // The customer's OWN environment is a tenant plane, not the root. From there the
    // organization is invisible even by primary key.
    $this->runAsEnvironment($result->environment, function () use ($organizationId): void {
        expect(Organization::query()->find($organizationId))->toBeNull()
            ->and(Organization::query()->count())->toBe(0);
    });

    // And with no environment in context at all, deny-by-default holds.
    $this->forgetEnvironment();
    expect(Organization::query()->find($organizationId))->toBeNull();
})->group('isolation');

it('refuses two projects with the same handle under one organization', function (): void {
    ownedProjectsRoot();
    $acme = provisionOwner('Acme', 'owner@acme.test');

    // The DATABASE refuses it. `createForOrganization()` picks a free slug rather than
    // colliding, so a writer reaching past it is the only way to prove the key exists —
    // and the key is what stops two products answering to one handle if a writer ever does.
    expect(fn () => Project::query()->create([
        'organization_id' => $acme->organization->id,
        'name' => 'Acme',
        'slug' => $acme->project->slug,
    ]))->toThrow(QueryException::class);
});

it('answers ownership by organization id', function (): void {
    ownedProjectsRoot();
    $acme = provisionOwner('Acme', 'owner@acme.test');
    $globex = provisionOwner('Globex', 'owner@globex.test');

    $projects = app(OrganizationProjects::class);

    expect($projects->ownedByOrganization($acme->project->id, $acme->organization->id))->toBeTrue()
        // Another organization's product is not yours.
        ->and($projects->ownedByOrganization($globex->project->id, $acme->organization->id))->toBeFalse()
        ->and($projects->forOrganization($acme->organization->id)->pluck('id')->all())->toBe([$acme->project->id])
        ->and($projects->forOrganization($globex->organization->id)->pluck('id')->all())->toBe([$globex->project->id]);
})->group('security');
