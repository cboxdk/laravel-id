<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\Contracts\AccountMembers;
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
        ->and($result->environment->slug)->toBe('production')
        ->and($result->environment->status)->toBe('active')
        // The environment is OWNED by the account…
        ->and($result->environment->account_id)->toBe($result->account->id);
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
    $a = app(AccountProvisioner::class)->provision(accountBlueprint('Acme', 'a@acme.test'));
    $b = app(AccountProvisioner::class)->provision(accountBlueprint('Acme', 'b@acme.test'));

    expect($a->environment->slug)->toBe('production')
        ->and($b->environment->slug)->toBe('production-2')
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

it('lets an account add environments up to its plan limit, then refuses', function (): void {
    $provisioner = app(AccountProvisioner::class);
    $result = $provisioner->provision(accountBlueprint(limit: 2));
    $account = $result->account;

    // Limit is 2, one used by provisioning → one more is allowed…
    $staging = $provisioner->addEnvironment($account, 'Staging');
    expect($staging->slug)->toBe('staging')
        ->and($staging->account_id)->toBe($account->id)
        ->and(app(Account::class)->newQuery()->find($account->id))->not->toBeNull();

    // …and the third is refused by the plan.
    expect(fn () => $provisioner->addEnvironment($account, 'Dev'))
        ->toThrow(EnvironmentLimitReached::class);
});
