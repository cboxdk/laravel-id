<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Platform\Exceptions\EnvironmentLimitReached;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Platform\TenantProvisioner;
use Cbox\Id\Platform\ValueObjects\TenantBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Standing a whole customer up in one call: the organization they are, the owner who signs
 * in for them, that owner's membership, their first product, and that product's first
 * environment.
 *
 * THIS FILE USED TO TEST THE MEMBER PLANE TOO — invite, activate, reset, remove, transfer
 * ownership, scope a member to environments — because `AccountMembers` was a parallel
 * people-API that only the account plane had. Those verbs are ordinary memberships and
 * subjects now, and they are tested where they live: MembershipServiceTest (add, change,
 * remove, the sole-owner refusal, isolation between organizations), InvitationServiceTest
 * (pending invites, accepting, replayed and cross-environment tokens),
 * MembershipEnvironmentGrantTest (per-member environment restriction) and the Identity
 * suite (passwords). Re-pointing them here would have been a second copy of coverage that
 * already exists, against a contract this class does not own.
 *
 * What is left is provisioning itself: the shape of what comes back, where each piece
 * lives, and the two refusals this class alone is responsible for.
 */
function tenantBlueprint(string $name = 'Acme', string $email = 'owner@acme.test', int $limit = 2): TenantBlueprint
{
    return new TenantBlueprint(
        organizationName: $name,
        ownerEmail: $email,
        ownerName: 'Acme Owner',
        ownerPassword: 'supersecret123',
        environmentLimit: $limit,
    );
}

it('provisions an organization, an owner, a product and its first environment', function (): void {
    platformRootEnvironment();

    $result = app(TenantProvisioner::class)->provision(tenantBlueprint());

    expect($result->organization->name)->toBe('Acme')
        ->and($result->owner->email)->toBe('owner@acme.test')
        // The authority is the MEMBERSHIP, not the identity: the same person can own this
        // organization and be a viewer in another.
        ->and($result->membership->role)->toBe(MembershipRole::Owner)
        ->and($result->membership->organization_id)->toBe($result->organization->id)
        ->and($result->membership->user_id)->toBe($result->owner->id)
        // Read BACK, not off the returned model: `all_environments` comes from the column
        // default rather than from the insert, so the in-memory model has no value for it
        // and answers null. The unrestricted owner is a fact about the row.
        ->and($result->membership->refresh()->all_environments)->toBeTrue()
        // The routing slug derives from the PRODUCT's name, not the stage name.
        ->and($result->environment->slug)->toBe('acme')
        ->and($result->environment->name)->toBe('Production')
        ->and($result->environment->status)->toBe(EnvironmentStatus::Active)
        // Ownership runs environment → project → organization, with no shortcut column.
        ->and($result->project->name)->toBe('Acme')
        ->and($result->project->organization_id)->toBe($result->organization->id)
        ->and($result->project->environment_limit)->toBe(2)
        ->and($result->environment->project_id)->toBe($result->project->id);
});

it('homes the organization in the platform root, not in the environment it just made', function (): void {
    $root = platformRootEnvironment();

    $result = app(TenantProvisioner::class)->provision(tenantBlueprint());

    // The customer's own environment is where their END USERS live. The row that identifies
    // the customer belongs in the root, and reading it needs the global scopes lifted
    // precisely because it is environment-owned.
    $organization = Organization::query()
        ->withoutGlobalScopes()
        ->whereKey($result->organization->id)
        ->first();

    expect($organization)->not->toBeNull()
        ->and($organization->environment_id)->toBe($root->id)
        ->and($organization->environment_id)->not->toBe($result->environment->id);
});

it('refuses to provision at all when the deployment has no platform root', function (): void {
    // There used to be a bootstrap window here: provisioning without a root produced a
    // customer whose organization did not exist and whose owner had nowhere to be a member,
    // and every caller downstream carried a null check for a state only a broken install
    // could reach. Refusing is the whole point — half a customer is worse than an error.
    expect(fn () => app(TenantProvisioner::class)->provision(tenantBlueprint()))
        ->toThrow(InvalidArgumentException::class);
});

it('provisions the environment empty — the management plane never seeds tenants', function (): void {
    platformRootEnvironment();

    $result = app(TenantProvisioner::class)->provision(tenantBlueprint());

    app(EnvironmentContext::class)->runAs($result->environment, function (): void {
        expect(Organization::query()->count())->toBe(0)
            ->and(app(Subjects::class)->findByEmail('owner@acme.test'))->toBeNull();
    });
});

it('gives each environment a unique routing slug', function (): void {
    platformRootEnvironment();

    // Two customers who happen to share a name still get distinct subdomains.
    $a = app(TenantProvisioner::class)->provision(tenantBlueprint('Acme', 'a@acme.test'));
    $b = app(TenantProvisioner::class)->provision(tenantBlueprint('Acme', 'b@acme.test'));

    expect($a->environment->slug)->toBe('acme')
        ->and($b->environment->slug)->toBe('acme-2')
        ->and($a->environment->id)->not->toBe($b->environment->id)
        // …and so do their organizations, which share the same rule inside the root.
        ->and($a->organization->slug)->toBe('acme')
        ->and($b->organization->slug)->toBe('acme-2');
});

it('lets one organization own several independently-billed products', function (): void {
    platformRootEnvironment();
    $provisioner = app(TenantProvisioner::class);
    $result = $provisioner->provision(tenantBlueprint());

    // A second product under the SAME organization — no second login, own allowance.
    $second = $provisioner->addProject($result->organization, 'Product Two', environmentLimit: 1);

    expect($second->organization_id)->toBe($result->organization->id)
        ->and($second->name)->toBe('Product Two')
        ->and($second->slug)->toBe('product-two')
        ->and($second->id)->not->toBe($result->project->id)
        // Billing attaches to the PRODUCT, so this allowance is its own rather than a draw
        // on a shared organization-level pool — which is why no such pool exists.
        ->and($second->environment_limit)->toBe(1);

    // The second product's first environment routes off the PRODUCT name, so it cannot
    // collide with the first product's subdomain.
    $environment = $provisioner->addEnvironment($second, 'Production');

    expect($environment->slug)->toBe('product-two')
        ->and($environment->project_id)->toBe($second->id);
});

it('provisions production, and can add a sandbox alongside it', function (): void {
    platformRootEnvironment();
    $result = app(TenantProvisioner::class)->provision(tenantBlueprint(limit: 3));

    expect($result->environment->type)->toBe(EnvironmentType::Production)
        ->and($result->environment->isSandbox())->toBeFalse();

    $sandbox = app(TenantProvisioner::class)
        ->addEnvironment($result->project, 'Sandbox', null, EnvironmentType::Sandbox);

    expect($sandbox->type)->toBe(EnvironmentType::Sandbox)
        ->and($sandbox->isSandbox())->toBeTrue();
});

it('lets a product add environments up to its plan limit, then refuses', function (): void {
    platformRootEnvironment();
    $provisioner = app(TenantProvisioner::class);
    $result = $provisioner->provision(tenantBlueprint(limit: 2));

    // The PRODUCT's limit is 2, one spent by provisioning → one more is allowed…
    $staging = $provisioner->addEnvironment($result->project, 'Staging');

    expect($staging->slug)->toBe('acme-staging')
        ->and($staging->project_id)->toBe($result->project->id);

    // …and the third is refused by the plan.
    expect(fn () => $provisioner->addEnvironment($result->project, 'Dev'))
        ->toThrow(EnvironmentLimitReached::class);
});

it('counts the limit against the product, not the organization', function (): void {
    platformRootEnvironment();
    $provisioner = app(TenantProvisioner::class);
    $result = $provisioner->provision(tenantBlueprint(limit: 1));

    // The first product is already at its limit of one…
    expect(fn () => $provisioner->addEnvironment($result->project, 'Blocked'))
        ->toThrow(EnvironmentLimitReached::class);

    // …which says nothing about a second product's own allowance.
    $second = $provisioner->addProject($result->organization, 'Product Two', environmentLimit: 1);

    expect($provisioner->addEnvironment($second, 'Production')->project_id)->toBe($second->id);
});

it('resolves the owner as an ordinary subject in the platform root', function (): void {
    platformRootEnvironment();
    $result = app(TenantProvisioner::class)->provision(tenantBlueprint());

    // One credential of record, in the root — the same row shape a tenant's own end user
    // occupies, rather than a member row with its own password column. That second column
    // is what made "who is signed in" a question with two answers.
    $found = app(PlatformRoot::class)->run(
        fn () => app(Subjects::class)->findByEmail('owner@acme.test'),
    );

    expect($found)->not->toBeNull()
        ->and($found->id)->toBe($result->owner->id);
});
