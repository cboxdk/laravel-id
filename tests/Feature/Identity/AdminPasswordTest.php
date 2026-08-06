<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\AdminPasswords;
use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\PasswordRevocationScope;
use Cbox\Id\Identity\Exceptions\PolicyViolation;
use Cbox\Id\Identity\ValueObjects\AdminPasswordAssignment;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function adminPwSubject(string $email = 'dana@acme.test'): string
{
    return app(Subjects::class)->create($email, 'Dana', 'the-original-passphrase')->id;
}

it('sets a temporary password that authenticates and requires a change', function (): void {
    $id = adminPwSubject();
    $admin = app(AdminPasswords::class);

    $admin->assign(new AdminPasswordAssignment(
        userId: $id,
        password: 'a-handed-over-temporary-passphrase',
        temporary: true,
    ));

    $subjects = app(Subjects::class);

    // The new credential works and the old one is dead.
    expect($subjects->verifyPassword($id, 'a-handed-over-temporary-passphrase'))->toBeTrue()
        ->and($subjects->verifyPassword($id, 'the-original-passphrase'))->toBeFalse();

    // ...but the subject cannot simply carry on with it.
    expect($admin->requiresChange($id))->toBeTrue()
        ->and($admin->hasExpired($id))->toBeFalse();
});

it('sets a persistent password with no standing change requirement', function (): void {
    $id = adminPwSubject('sam@acme.test');
    $admin = app(AdminPasswords::class);

    $admin->assign(new AdminPasswordAssignment(
        userId: $id,
        password: 'a-permanent-administrator-passphrase',
        temporary: false,
    ));

    expect(app(Subjects::class)->verifyPassword($id, 'a-permanent-administrator-passphrase'))->toBeTrue()
        ->and($admin->requiresChange($id))->toBeFalse();
});

it('expires a temporary password at its deadline', function (): void {
    $id = adminPwSubject('rae@acme.test');
    $admin = app(AdminPasswords::class);

    $admin->assign(new AdminPasswordAssignment(
        userId: $id,
        password: 'a-short-lived-temporary-passphrase',
        temporary: true,
        expiresAt: now()->subMinute(),
    ));

    // Past its deadline the hand-off credential must not admit anyone, even though the
    // hash still matches — the sign-in flow gates on this.
    expect($admin->hasExpired($id))->toBeTrue();
});

it('revokes sessions and grants according to the chosen scope', function (): void {
    $sessions = app(SessionManager::class);
    $admin = app(AdminPasswords::class);

    // Sessions-and-tokens (the default): the subject is signed out everywhere.
    $cut = adminPwSubject('cut@acme.test');
    $cutSession = $sessions->start($cut, null, ['pwd'])->id;
    $admin->assign(new AdminPasswordAssignment(
        userId: $cut,
        password: 'a-replacement-passphrase-for-cut',
        revoke: PasswordRevocationScope::SessionsAndTokens,
    ));
    expect($sessions->active($cutSession))->toBeNull();

    // Nothing: a lockout recovery that must not disturb the person's open sessions.
    $keep = adminPwSubject('keep@acme.test');
    $keepSession = $sessions->start($keep, null, ['pwd'])->id;
    $admin->assign(new AdminPasswordAssignment(
        userId: $keep,
        password: 'a-replacement-passphrase-for-keep',
        revoke: PasswordRevocationScope::Nothing,
    ));
    expect($sessions->active($keepSession))->not->toBeNull();
});

it('records an audit event naming the actor and the choices made', function (): void {
    $id = adminPwSubject('audited@acme.test');

    app(AdminPasswords::class)->assign(new AdminPasswordAssignment(
        userId: $id,
        password: 'an-audited-replacement-passphrase',
        temporary: true,
        revoke: PasswordRevocationScope::SessionsOnly,
        actorType: 'organization_member',
        actorId: 'member_42',
        reason: 'Locked out after losing their phone',
    ));

    $entry = AuditEntry::query()->where('action', 'user.password_set_by_admin')->sole();

    expect($entry->target_id)->toBe($id)
        ->and($entry->actor_id)->toBe('member_42')
        ->and($entry->context['temporary'])->toBeTrue()
        ->and($entry->context['revoked'])->toBe('sessions_only')
        ->and($entry->context['reason'])->toBe('Locked out after losing their phone');
});

// An administrator is not exempt from the tenant's policy: a credential they hand out is
// one the person may keep using, so the weakest password on the platform must not be the
// one issued from behind the highest privilege.
it('holds an administrator to the tenant password policy', function (): void {
    $id = adminPwSubject('policed@acme.test');
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(minLength: 20, requireBreachCheck: false));

    expect(fn () => app(AdminPasswords::class)->assign(
        new AdminPasswordAssignment($id, 'too-short-for-us')
    ))->toThrow(PolicyViolation::class, 'at least 20 characters');

    // The credential was NOT changed by the refused attempt.
    expect(app(Subjects::class)->verifyPassword($id, 'the-original-passphrase'))->toBeTrue();

    // A conforming one is accepted.
    app(AdminPasswords::class)->assign(
        new AdminPasswordAssignment($id, 'a-sufficiently-long-replacement-passphrase')
    );
    expect(app(Subjects::class)->verifyPassword($id, 'a-sufficiently-long-replacement-passphrase'))->toBeTrue();
});

it('clears the requirement once the subject chooses their own password', function (): void {
    $id = adminPwSubject('cleared@acme.test');
    $admin = app(AdminPasswords::class);

    $admin->assign(new AdminPasswordAssignment($id, 'a-temporary-handover-passphrase', temporary: true));
    expect($admin->requiresChange($id))->toBeTrue();

    $admin->clear($id);
    expect($admin->requiresChange($id))->toBeFalse();
});
