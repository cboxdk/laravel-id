<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Exceptions\PolicyViolation;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\Contracts\AccountMembers;
use Cbox\Id\Platform\Enums\AccountRole;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/**
 * Account members are ordinary subjects in the platform-root environment, not a second
 * credential store. These tests pin the properties that makes true:
 * the credential of record moves to the subject, an invitation is not yet an identity,
 * and adding an email to an account never re-credentials the person behind it.
 *
 * See docs/core-concepts/unified-account-identity.md.
 */

/** Stand up the platform-root environment — "tenant 1", where account identities live. */
function platformRootEnvironment(): Environment
{
    return Environment::query()->create([
        'name' => 'Platform',
        'slug' => 'platform-'.Str::lower((string) Str::ulid()),
        'type' => EnvironmentType::Production,
        'status' => EnvironmentStatus::Active,
        'is_default' => true,
        'settings' => [],
    ]);
}

function provisionHomedAccount(string $email = 'owner@acme.test', string $password = 'a-strong-unbreached-passphrase'): object
{
    return app(AccountProvisioner::class)->provision(new AccountBlueprint(
        accountName: 'Acme',
        ownerEmail: $email,
        ownerName: 'Acme Owner',
        ownerPassword: $password,
    ));
}

it('gives an account member a subject in the platform root and a membership in the account org', function (): void {
    $root = platformRootEnvironment();
    $result = provisionHomedAccount();

    $member = app(AccountMembers::class)->find($result->member->id);
    expect($member?->subject_id)->not->toBeNull();

    // The subject lives in the platform root — not in the environment the account was
    // just given, which stays empty of tenants.
    app(EnvironmentContext::class)->runAs($root, function () use ($member, $result): void {
        $subject = app(Subjects::class)->find((string) $member->subject_id);

        expect($subject)->not->toBeNull()
            ->and($subject->email)->toBe('owner@acme.test')
            // …and they are placed in the ORGANIZATION that represents the account, which
            // is what makes account SSO an ordinary connection rather than a second stack.
            ->and(app(Memberships::class)->of(
                (string) $result->account->refresh()->organization_id,
                (string) $member->subject_id,
            ))->not->toBeNull();
    });

    // Not in the account's own tenant environment — the planes stay separate.
    app(EnvironmentContext::class)->runAs($result->environment, function () use ($member): void {
        expect(app(Subjects::class)->find((string) $member->subject_id))->toBeNull();
    });
});

it('makes the SUBJECT the credential of record — the member row is no longer consulted', function (): void {
    $root = platformRootEnvironment();
    $result = provisionHomedAccount();
    $members = app(AccountMembers::class);
    $subjectId = (string) $members->find($result->member->id)?->subject_id;

    expect($members->verifyPassword($result->member->id, 'a-strong-unbreached-passphrase'))->toBeTrue();

    // Rotate the credential on the SUBJECT only, behind the account layer's back. If the
    // member row were still a credential store the old password would keep working —
    // that is exactly the second store this design removes.
    app(EnvironmentContext::class)->runAs($root, fn () => app(Subjects::class)->setPassword($subjectId, 'rotated-on-the-subject'));

    expect($members->verifyPassword($result->member->id, 'a-strong-unbreached-passphrase'))->toBeFalse()
        ->and($members->verifyPassword($result->member->id, 'rotated-on-the-subject'))->toBeTrue();
});

it('mints an invited member\'s subject deactivated, so an invitation is not yet a way in', function (): void {
    $root = platformRootEnvironment();
    $result = provisionHomedAccount();
    $members = app(AccountMembers::class);

    $invited = $members->invite($result->account->id, 'invitee@acme.test', AccountRole::Developer);
    $subjectId = (string) $members->find($invited->id)?->subject_id;

    expect($subjectId)->not->toBe('');

    // The subject exists (it holds their place in the org) but cannot authenticate.
    app(EnvironmentContext::class)->runAs($root, function () use ($subjectId): void {
        expect(app(Subjects::class)->isActive($subjectId))->toBeFalse();
    });

    // Accepting sets the password ON THE SUBJECT and activates it.
    expect($members->activate($invited->id, 'the-invitees-own-passphrase'))->toBeTrue();

    app(EnvironmentContext::class)->runAs($root, function () use ($subjectId): void {
        expect(app(Subjects::class)->isActive($subjectId))->toBeTrue()
            ->and(app(Subjects::class)->verifyPassword($subjectId, 'the-invitees-own-passphrase'))->toBeTrue();
    });

    expect($members->verifyPassword($invited->id, 'the-invitees-own-passphrase'))->toBeTrue();
});

it('writes a password reset through to the subject', function (): void {
    $root = platformRootEnvironment();
    $result = provisionHomedAccount();
    $members = app(AccountMembers::class);
    $subjectId = (string) $members->find($result->member->id)?->subject_id;

    expect($members->resetPassword($result->member->id, 'brand-new-passphrase'))->toBeTrue();

    app(EnvironmentContext::class)->runAs($root, function () use ($subjectId): void {
        expect(app(Subjects::class)->verifyPassword($subjectId, 'brand-new-passphrase'))->toBeTrue();
    });
});

it('never re-credentials an existing subject when their email is added to an account', function (): void {
    $root = platformRootEnvironment();

    // A person who already has a Cbox ID identity, with a password only they know.
    $existing = app(EnvironmentContext::class)->runAs(
        $root,
        fn () => app(Subjects::class)->create('victim@example.test', 'Victim', 'the-password-only-they-know'),
    );

    $result = provisionHomedAccount();

    // Someone with an account invites that address. The invitation must not hand the
    // inviter a credential for an identity that predates it.
    $members = app(AccountMembers::class);
    $invited = $members->invite($result->account->id, 'victim@example.test', AccountRole::Admin);

    expect($members->find($invited->id)?->subject_id)->toBe($existing->id);

    app(EnvironmentContext::class)->runAs($root, function () use ($existing): void {
        expect(app(Subjects::class)->isActive($existing->id))->toBeTrue()
            ->and(app(Subjects::class)->verifyPassword($existing->id, 'the-password-only-they-know'))->toBeTrue();
    });

    // …and accepting does not overwrite it either: the identity already had a credential,
    // so acceptance only confers the membership.
    $members->activate($invited->id, 'attacker-chosen-passphrase');

    app(EnvironmentContext::class)->runAs($root, function () use ($existing): void {
        expect(app(Subjects::class)->verifyPassword($existing->id, 'attacker-chosen-passphrase'))->toBeFalse()
            ->and(app(Subjects::class)->verifyPassword($existing->id, 'the-password-only-they-know'))->toBeTrue();
    });
});

it('revokes the organization membership and deactivates the subject when a member is removed', function (): void {
    $root = platformRootEnvironment();
    $result = provisionHomedAccount();
    $members = app(AccountMembers::class);
    $organizationId = (string) $result->account->refresh()->organization_id;

    $mate = $members->invite($result->account->id, 'mate@acme.test', AccountRole::Developer);
    $members->activate($mate->id, 'their-own-passphrase');
    $subjectId = (string) $members->find($mate->id)?->subject_id;

    expect($members->remove($mate->id))->toBeTrue();

    app(EnvironmentContext::class)->runAs($root, function () use ($organizationId, $subjectId): void {
        // Removal is not cosmetic: the place in the account's organization is gone…
        expect(app(Memberships::class)->of($organizationId, $subjectId))->toBeNull()
            // …and the identity that existed to be this account's member cannot sign in.
            ->and(app(Subjects::class)->isActive($subjectId))->toBeFalse();
    });
});

it('falls back to the local hash only while no platform root exists (the bootstrap window)', function (): void {
    // No is_default environment, and no configured default either — the very first
    // install, before there is anywhere for a subject to live.
    config(['cbox-id.environments.default' => null]);
    Environment::query()->where('is_default', true)->update(['is_default' => false]);

    $result = provisionHomedAccount('founder@bootstrap.test', 'the-founders-passphrase');
    $members = app(AccountMembers::class);

    expect($members->find($result->member->id)?->subject_id)->toBeNull()
        // The founder is not locked out of the deployment they are creating…
        ->and($members->verifyPassword($result->member->id, 'the-founders-passphrase'))->toBeTrue()
        ->and($members->verifyPassword($result->member->id, 'wrong-passphrase'))->toBeFalse();
});

it('resolves the account membership from the subject — the lookup the admin session depends on', function (): void {
    platformRootEnvironment();
    $result = provisionHomedAccount();
    $members = app(AccountMembers::class);
    $subjectId = (string) $members->find($result->member->id)?->subject_id;

    expect($members->findBySubject($subjectId)?->id)->toBe($result->member->id)
        // Deny-by-default: an unknown or blank subject is nobody's member.
        ->and($members->findBySubject('no-such-subject'))->toBeNull()
        ->and($members->findBySubject(''))->toBeNull();
});

it('names the platform root by its is_default row, falling back to the configured default', function (): void {
    // A configured key with no environment behind it is not a platform root. Accepting
    // it would produce organizations and subjects pointing at an environment that does
    // not exist.
    config(['cbox-id.environments.default' => 'env_configured_root']);
    expect(app(PlatformRoot::class)->environment())->toBeNull();

    $unowned = Environment::query()->create([
        'name' => 'Configured',
        'slug' => 'configured-'.Str::lower((string) Str::ulid()),
        'type' => EnvironmentType::Production,
        'status' => EnvironmentStatus::Active,
        'is_default' => false,
        'settings' => [],
    ]);

    config(['cbox-id.environments.default' => $unowned->id]);

    expect(app(PlatformRoot::class)->model())->toBeNull()
        ->and(app(PlatformRoot::class)->environment()?->environmentKey())->toBe($unowned->id);

    // A stamped row is authoritative — it wins over per-process configuration.
    $root = platformRootEnvironment();
    expect(app(PlatformRoot::class)->model()?->id)->toBe($root->id)
        ->and(app(PlatformRoot::class)->environment()?->environmentKey())->toBe($root->id);
});

/**
 * The platform root is where the platform's OWN people are written as subjects. Pointing
 * it at a customer's environment would put every account member inside that tenant, where
 * its environment admins — including a Developer, a role explicitly denied the member
 * roster — could set their password through the admin-password feature and sign in as
 * them. A misaimed config key must resolve to nothing, not to a customer.
 */
it('refuses a configured default that belongs to an account', function (): void {
    $result = provisionHomedAccount();

    $tenant = Environment::query()->create([
        'name' => 'Acme production',
        'slug' => 'acme-'.Str::lower((string) Str::ulid()),
        'type' => EnvironmentType::Production,
        'status' => EnvironmentStatus::Active,
        'is_default' => false,
        'account_id' => $result->account->id,
        'settings' => [],
    ]);

    config(['cbox-id.environments.default' => $tenant->id]);

    // No is_default row, and the only candidate is owned — so there is no root at all,
    // and run() degrades to null rather than writing into the customer.
    Environment::query()->where('is_default', true)->update(['is_default' => false]);

    expect(app(PlatformRoot::class)->environment())->toBeNull()
        ->and(app(PlatformRoot::class)->run(fn (): string => 'ran'))->toBeNull();
});

/**
 * The account member row carries a fallback password column, and the reset also burns
 * the link by bumping session_version. Since the subject write can now REFUSE — the
 * tenant's policy applies there — both must be inside the same transaction, or a
 * rejected password lands in the fallback column and spends the link on its way out.
 */
it('rolls the whole reset back when the policy refuses the new password', function (): void {
    $root = platformRootEnvironment();
    $result = provisionHomedAccount();
    $members = app(AccountMembers::class);

    app(EnvironmentContext::class)->runAs(
        $root,
        fn () => app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(minLength: 40)),
    );

    $before = $members->find($result->member->id);
    $stampBefore = $before?->session_version;

    expect(fn () => $members->resetPassword($result->member->id, 'nowhere-near-forty-characters'))
        ->toThrow(PolicyViolation::class);

    $after = $members->find($result->member->id);

    // The link is unspent and the rejected password is nowhere.
    expect($after?->session_version)->toBe($stampBefore)
        ->and($members->verifyPassword($result->member->id, 'nowhere-near-forty-characters'))->toBeFalse();
});
