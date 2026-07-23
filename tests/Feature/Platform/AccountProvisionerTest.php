<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\Contracts\AccountMembers;
use Cbox\Id\Platform\Contracts\Accounts;
use Cbox\Id\Platform\Enums\AccountRole;
use Cbox\Id\Platform\Exceptions\AccountSuspended;
use Cbox\Id\Platform\Exceptions\EnvironmentLimitReached;
use Cbox\Id\Platform\Models\Account;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function accountBlueprint(string $name = 'Acme', string $email = 'owner@acme.test', int $limit = 2): AccountBlueprint
{
    return new AccountBlueprint(
        accountName: $name,
        ownerEmail: $email,
        ownerName: 'Acme Owner',
        ownerPassword: 'supersecret123',
        environmentLimit: $limit,
    );
}

it('provisions an account with a member and a first environment', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint());

    expect($result->account->name)->toBe('Acme')
        ->and($result->account->environment_limit)->toBe(2)
        ->and($result->member->email)->toBe('owner@acme.test')
        ->and($result->member->account_id)->toBe($result->account->id)
        // The routing slug derives from the ACCOUNT name, not the stage name.
        ->and($result->environment->slug)->toBe('acme')
        ->and($result->environment->name)->toBe('Production')
        ->and($result->environment->status)->toBe('active')
        // The environment is OWNED by the account…
        ->and($result->environment->account_id)->toBe($result->account->id)
        // …through a first PROJECT (the account's first IdP product), named after
        // the account and carrying the plan's environment allowance.
        ->and($result->project->name)->toBe('Acme')
        ->and($result->project->account_id)->toBe($result->account->id)
        ->and($result->project->environment_limit)->toBe(2)
        ->and($result->environment->project_id)->toBe($result->project->id);
});

it('lets one account own several independently-billed projects (IdP products)', function (): void {
    $provisioner = app(AccountProvisioner::class);
    $result = $provisioner->provision(accountBlueprint());

    // A second product under the SAME account — no second login, own env allowance.
    $second = $provisioner->addProject($result->account, 'Product Two', environmentLimit: 1);

    expect($second->account_id)->toBe($result->account->id)
        ->and($second->name)->toBe('Product Two')
        ->and($second->slug)->toBe('product-two')
        ->and($second->id)->not->toBe($result->project->id)
        // Its environment allowance is its own (per-project billing), independent of
        // the first project's.
        ->and($second->environment_limit)->toBe(1);

    // The second project's first environment routes off the PROJECT name, not the
    // account name — so it doesn't collide with the first product's subdomain.
    $env = $provisioner->addEnvironment($second, 'Production');
    expect($env->slug)->toBe('product-two')
        ->and($env->project_id)->toBe($second->id)
        ->and($env->account_id)->toBe($result->account->id);
});

it('provisions the environment empty — the account plane never seeds tenants', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint());

    // …and starts empty of end-user tenants: no organizations, no subjects. The
    // member administers it from the root; orgs/users come later, inside the env.
    app(EnvironmentContext::class)->runAs($result->environment, function (): void {
        expect(Organization::query()->count())->toBe(0);
    });
});

it('gives each environment a unique routing slug', function (): void {
    // Two different accounts that happen to share a name still get distinct
    // subdomains — the slug is globally unique.
    $a = app(AccountProvisioner::class)->provision(accountBlueprint('Acme', 'a@acme.test'));
    $b = app(AccountProvisioner::class)->provision(accountBlueprint('Acme', 'b@acme.test'));

    expect($a->environment->slug)->toBe('acme')
        ->and($b->environment->slug)->toBe('acme-2')
        ->and($a->environment->id)->not->toBe($b->environment->id);
});

it('resolves a member globally by email — the answer to "which account"', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint());

    $members = app(AccountMembers::class);
    $found = $members->findByEmail('owner@acme.test');

    expect($found)->not->toBeNull()
        ->and($found->account_id)->toBe($result->account->id)
        ->and($members->verifyPassword($found->id, 'supersecret123'))->toBeTrue()
        ->and($members->verifyPassword($found->id, 'wrong-password'))->toBeFalse();
});

it('provisions a production environment and can add a sandbox', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint(limit: 3));

    expect($result->environment->type)->toBe(EnvironmentType::Production)
        ->and($result->environment->isSandbox())->toBeFalse();

    $sandbox = app(AccountProvisioner::class)->addEnvironment($result->project, 'Sandbox', null, EnvironmentType::Sandbox);

    expect($sandbox->type)->toBe(EnvironmentType::Sandbox)
        ->and($sandbox->isSandbox())->toBeTrue();
});

it('provisions the owner with the Owner role and every environment', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint());

    expect($result->member->role)->toBe(AccountRole::Owner)
        ->and($result->member->all_environments)->toBeTrue();
});

it('invites a member with a role who cannot authenticate until they accept', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint());
    $members = app(AccountMembers::class);

    $invited = $members->invite($result->account->id, 'teammate@acme.test', AccountRole::Developer, 'Team Mate');

    expect($invited->status->value)->toBe('invited')
        ->and($invited->role)->toBe(AccountRole::Developer)
        ->and($invited->account_id)->toBe($result->account->id)
        // Invited members are inactive — no credential works, even a lucky guess.
        ->and($members->verifyPassword($invited->id, 'anything'))->toBeFalse();

    // Accepting sets a password and activates them.
    expect($members->activate($invited->id, 'their-own-passphrase'))->toBeTrue();
    $active = $members->find($invited->id);
    expect($active->status->value)->toBe('active')
        ->and($members->verifyPassword($invited->id, 'their-own-passphrase'))->toBeTrue();
});

it('scopes a member to specific environments and resolves their access', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint(limit: 3));
    $members = app(AccountMembers::class);
    $prod = $result->environment;
    $staging = app(AccountProvisioner::class)->addEnvironment($result->project, 'Staging');

    $dev = $members->invite($result->account->id, 'dev@acme.test', AccountRole::Developer);
    // Restrict the developer to staging only (Stripe-style test-vs-prod access).
    $members->setEnvironmentAccess($dev->id, all: false, environmentIds: [$staging->id]);

    $access = $members->accessibleEnvironmentIds($members->find($dev->id));
    expect($access)->toBe([$staging->id])
        ->and($access)->not->toContain($prod->id);
});

it('never scopes an owner/admin and ignores foreign environment grants', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint());
    $members = app(AccountMembers::class);

    // Another account's environment — must never be grantable.
    $other = app(AccountProvisioner::class)->provision(accountBlueprint('Other', 'other@x.test'));

    $admin = $members->invite($result->account->id, 'admin@acme.test', AccountRole::Admin);
    // Admins can't be scoped down — the call is a no-op, access stays all.
    $members->setEnvironmentAccess($admin->id, all: false, environmentIds: [$other->environment->id]);

    $admin = $members->find($admin->id);
    expect($admin->all_environments)->toBeTrue()
        ->and($members->accessibleEnvironmentIds($admin))->toBe([$result->environment->id]);
});

it('refuses to re-activate an already-active member (replayed accept)', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint());
    $members = app(AccountMembers::class);

    // The provisioned owner is already active — a replayed accept must not reset it.
    expect($members->activate($result->member->id, 'attacker-chosen-password'))->toBeFalse()
        ->and($members->verifyPassword($result->member->id, 'attacker-chosen-password'))->toBeFalse()
        ->and($members->verifyPassword($result->member->id, 'supersecret123'))->toBeTrue();
});

it('removes a member but refuses to remove an owner', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint());
    $members = app(AccountMembers::class);
    $mate = $members->invite($result->account->id, 'mate@acme.test', AccountRole::Developer);

    expect($members->remove($mate->id))->toBeTrue()
        ->and($members->find($mate->id))->toBeNull();

    // The owner can't be removed — that would orphan the account.
    expect($members->remove($result->member->id))->toBeFalse()
        ->and($members->find($result->member->id))->not->toBeNull();
});

it('transfers ownership, promoting one member and demoting the old owner', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint());
    $members = app(AccountMembers::class);
    $successor = $members->invite($result->account->id, 'next@acme.test', AccountRole::Admin);
    $members->activate($successor->id, 'successor-passphrase');

    $members->transferOwnership($result->account->id, $successor->id);

    expect($members->find($successor->id)->role)->toBe(AccountRole::Owner)
        ->and($members->find($successor->id)->all_environments)->toBeTrue()
        // The former owner is demoted to admin, not removed.
        ->and($members->find($result->member->id)->role)->toBe(AccountRole::Admin);
});

it('resets an active member\'s password but never an invited one', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint());
    $members = app(AccountMembers::class);

    expect($members->resetPassword($result->member->id, 'brand-new-passphrase'))->toBeTrue()
        ->and($members->verifyPassword($result->member->id, 'brand-new-passphrase'))->toBeTrue();

    // An invited member can't be reset — they must accept the invitation first.
    $invited = $members->invite($result->account->id, 'inv@acme.test', AccountRole::Viewer);
    expect($members->resetPassword($invited->id, 'sneaky-passphrase'))->toBeFalse()
        ->and($members->find($invited->id)?->status?->value)->toBe('invited');
});

it('refuses to add an environment for a suspended account', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint(limit: 3));
    app(Accounts::class)->suspend($result->account->id);

    expect(fn () => app(AccountProvisioner::class)->addEnvironment($result->project, 'Blocked'))
        ->toThrow(AccountSuspended::class);
});

it('renames an account', function (): void {
    $result = app(AccountProvisioner::class)->provision(accountBlueprint());

    app(Accounts::class)->rename($result->account->id, 'Renamed Co');

    expect(app(Accounts::class)->find($result->account->id)->name)->toBe('Renamed Co');
});

it('lets a project add environments up to its plan limit, then refuses', function (): void {
    $provisioner = app(AccountProvisioner::class);
    $result = $provisioner->provision(accountBlueprint(limit: 2));
    $project = $result->project;

    // The PROJECT's limit is 2, one used by provisioning → one more is allowed…
    $staging = $provisioner->addEnvironment($project, 'Staging');
    expect($staging->slug)->toBe('acme-staging')
        ->and($staging->account_id)->toBe($result->account->id)
        ->and($staging->project_id)->toBe($project->id)
        ->and(app(Account::class)->newQuery()->find($result->account->id))->not->toBeNull();

    // …and the third is refused by the plan.
    expect(fn () => $provisioner->addEnvironment($project, 'Dev'))
        ->toThrow(EnvironmentLimitReached::class);
});
