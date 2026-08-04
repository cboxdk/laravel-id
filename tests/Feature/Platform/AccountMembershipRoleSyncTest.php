<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\Contracts\AccountMembers;
use Cbox\Id\Platform\Enums\AccountRole;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * The membership is what the console asks, so it has to say what the member holds — at
 * placement and at every role change after it.
 *
 * It used to say `member` for everybody, deliberately: `AccountRole` on the member row was
 * the single authority and mirroring it would have been a second truth to drift. Once the
 * console reads the membership that abstention becomes the wrong answer to the only
 * question, and it makes an account's owner a plain member of the organization they own.
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

function roleOnAccountOrg(string $subjectId): ?MembershipRole
{
    return app(PlatformRoot::class)->run(
        fn (): ?MembershipRole => app(Memberships::class)->forUser($subjectId)->first()?->role,
    );
}

function accountForRoleSync(string $email = 'owner@acme.test'): object
{
    return app(AccountProvisioner::class)->provision(
        new AccountBlueprint('Acme', $email, 'Owner', 'a-strong-unbreached-passphrase'),
    );
}

it('places an account owner as an owner of its organization', function (): void {
    $result = accountForRoleSync();

    expect(roleOnAccountOrg((string) $result->member->subject_id))
        ->toBe(MembershipRole::Owner);
})->group('security');

it('carries a role change onto the membership', function (): void {
    $result = accountForRoleSync();
    $members = app(AccountMembers::class);

    $invited = $members->create($result->account->id, 'dev@acme.test', 'a-strong-unbreached-passphrase', 'Dev');
    $members->setRole($invited->id, AccountRole::Developer);

    // Without this the two answers separate on the first role change: the member row says
    // Developer, the membership still says whatever it was placed with, and every
    // capability the console reads comes from the second one. A role change that changes
    // nothing is the worst kind, because the screen confirms it worked.
    expect(roleOnAccountOrg((string) $invited->refresh()->subject_id))
        ->toBe(MembershipRole::Developer);
})->group('security');

it('maps a billing member to a viewer, losing only what nothing asks for', function (): void {
    $result = accountForRoleSync();
    $members = app(AccountMembers::class);

    $invited = $members->create($result->account->id, 'money@acme.test', 'a-strong-unbreached-passphrase', 'Money');
    $members->setRole($invited->id, AccountRole::Billing);

    // MembershipRole has no billing case and must not gain one: `canWrite()` is "not a
    // Viewer", so a billing role would arrive holding write access to every organization
    // on every tenant. Viewer keeps the reachable half — reading the plan — and drops
    // `canManageBilling()`, which no page and no route asks for.
    $role = roleOnAccountOrg((string) $invited->refresh()->subject_id);

    expect($role)->toBe(MembershipRole::Viewer)
        ->and($role->canReadBilling())->toBeTrue()
        ->and($role->canWrite())->toBeFalse();
})->group('security');

it('never re-roles a membership that has no account member behind it', function (): void {
    $result = accountForRoleSync();
    $members = app(AccountMembers::class);

    // An ordinary person in the account's organization — placed directly, no account
    // member row. Nothing the account plane does may move them.
    $bystander = strtolower((string) Str::ulid());
    app(PlatformRoot::class)->run(function () use ($result, $bystander): void {
        app(Memberships::class)->add(
            (string) $result->account->organization_id,
            $bystander,
            MembershipRole::Member,
        );
    });

    $invited = $members->create($result->account->id, 'dev@acme.test', 'a-strong-unbreached-passphrase', 'Dev');
    $members->setRole($invited->id, AccountRole::Admin);

    expect(roleOnAccountOrg($bystander))->toBe(MembershipRole::Member);
})->group('security');

it('re-roles the memberships an earlier backfill left neutral', function (): void {
    $result = accountForRoleSync();
    $subjectId = (string) $result->member->subject_id;
    $organizationId = (string) $result->account->organization_id;

    // The state 2026_08_05_000200 produced: placed, but neutral, because that was the
    // right answer while the member row was the authority.
    DB::table('memberships')
        ->where('organization_id', $organizationId)
        ->where('user_id', $subjectId)
        ->update(['role' => MembershipRole::Member->value]);

    expect(roleOnAccountOrg($subjectId))->toBe(MembershipRole::Member);

    /** @var object{up: callable} $migration */
    $migration = require dirname(__DIR__, 3).'/database/migrations/2026_08_06_000200_give_every_account_membership_its_members_role.php';
    $migration->up();

    expect(roleOnAccountOrg($subjectId))->toBe(MembershipRole::Owner);
});

it('refuses to demote the last owner, and writes nothing when it does', function (): void {
    $result = accountForRoleSync();
    $members = app(AccountMembers::class);

    // `remove()` has always refused to delete an owner, on the grounds that it could
    // orphan the account. Re-roling the same owner to Admin orphans it just as
    // thoroughly, and used to be allowed — it went unnoticed because only the member row
    // was written and nothing objected.
    $members->setRole($result->member->id, AccountRole::Admin);

    // BOTH rows, because the point is that they cannot disagree. Refusing after the
    // member row is written — which is what letting the organization's LastOwner guard
    // fire would do — leaves the account recording a demotion the organization declined.
    expect($result->member->refresh()->role)->toBe(AccountRole::Owner)
        ->and(roleOnAccountOrg((string) $result->member->subject_id))->toBe(MembershipRole::Owner);
})->group('security');

it('lets an owner step down once somebody else owns the account', function (): void {
    $result = accountForRoleSync();
    $members = app(AccountMembers::class);

    // Promote FIRST, demote second — which is what makes ownership transfer possible at
    // all now that the organization refuses to lose its final owner.
    $successor = $members->create($result->account->id, 'next@acme.test', 'a-strong-unbreached-passphrase', 'Next');
    $members->setRole($successor->id, AccountRole::Owner);
    $members->setRole($result->member->id, AccountRole::Admin);

    expect($result->member->refresh()->role)->toBe(AccountRole::Admin)
        ->and(roleOnAccountOrg((string) $result->member->subject_id))->toBe(MembershipRole::Admin)
        ->and(roleOnAccountOrg((string) $successor->refresh()->subject_id))->toBe(MembershipRole::Owner);
})->group('security');
