<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\LoginAttempts;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\MfaMandate;
use Cbox\Id\Identity\Contracts\PasswordExpiry;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Testing\InteractsWithOrganizations;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithOrganizations::class);

/**
 * `AuthPolicy` carried `maxAgeDays`, `mfa` and `lockoutThreshold` for a release with no
 * consumer for any of them: stored, inherited and tightened correctly, and read by
 * nothing. These tests are the difference between a policy and a preference.
 */
function policySubject(string $email = 'dana@corp.test'): string
{
    return app(Subjects::class)->create($email, 'Dana', 'a-perfectly-long-passphrase')->id;
}

// ---------------------------------------------------------------- max age

it('does not expire a password when the policy sets no maximum age', function (): void {
    $id = policySubject();

    expect(app(PasswordExpiry::class)->hasExpired($id))->toBeFalse();
});

it('expires a password once it outlives the policy maximum age', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(maxAgeDays: 30));

    $id = policySubject();

    expect(app(PasswordExpiry::class)->hasExpired($id))->toBeFalse();

    $this->travel(31)->days();

    expect(app(PasswordExpiry::class)->hasExpired($id))->toBeTrue();
});

it('restarts the clock when the password is set again', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(maxAgeDays: 30));

    $id = policySubject();
    $this->travel(31)->days();

    expect(app(PasswordExpiry::class)->hasExpired($id))->toBeTrue();

    app(Subjects::class)->setPassword($id, 'a-freshly-chosen-passphrase');

    expect(app(PasswordExpiry::class)->hasExpired($id))->toBeFalse();
});

/**
 * A subject whose credential predates the platform tracking this is not evidence of an
 * OLD password. Locking them out on that assumption is a worse failure than a clock that
 * starts late.
 */
it('does not expire a password it has no record of', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(maxAgeDays: 1));

    expect(app(PasswordExpiry::class)->hasExpired('user_never_recorded'))->toBeFalse();
});

it("takes the organization's shorter maximum age when the caller names none", function (): void {
    $policies = app(AuthPolicies::class);
    $policies->setForEnvironment(new AuthPolicy(maxAgeDays: 180));

    $org = $this->makeOrganization();
    $policies->setForOrganization($org->id, new AuthPolicy(maxAgeDays: 30));

    $id = policySubject();
    app(Memberships::class)->add($org->id, $id, MembershipRole::Member);

    $this->travel(31)->days();

    // 31 days is inside the environment's 180 and past the organization's 30.
    expect(app(PasswordExpiry::class)->hasExpired($id))->toBeTrue();
});

// ---------------------------------------------------------------- MFA mandate

it('demands no enrolment while MFA is optional', function (): void {
    $id = policySubject();

    expect(app(MfaMandate::class)->requiresEnrolment($id))->toBeFalse();
});

it('demands enrolment from a subject with no factor when MFA is required', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(mfa: MfaRequirement::Required));

    $id = policySubject();

    expect(app(MfaMandate::class)->requiresEnrolment($id))->toBeTrue();
});

it('is satisfied by a confirmed TOTP factor', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(mfa: MfaRequirement::Required));

    $id = policySubject();
    $mfa = app(Mfa::class);
    $enrollment = $mfa->enrollTotp($id, 'dana@corp.test', 'Cbox ID');
    $mfa->confirmTotp($id, app(TotpAuthenticator::class)->codeAt($enrollment->secret, time()));

    expect(app(MfaMandate::class)->requiresEnrolment($id))->toBeFalse();
});

/**
 * A passkey is usually the STRONGER factor — phishing-resistant and hardware-bound — so
 * treating it as not-a-factor would push people from a better credential to a worse one
 * to satisfy a policy meant to raise the bar.
 */
it('is satisfied by a registered passkey', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(mfa: MfaRequirement::Required));

    $id = policySubject();

    WebAuthnCredential::query()->create([
        'user_id' => $id,
        'credential_id' => 'cred-'.$id,
        'public_key' => 'pk',
        'sign_count' => 0,
    ]);

    expect(app(MfaMandate::class)->requiresEnrolment($id))->toBeFalse();
});

it("inherits an organization's MFA mandate when the caller names none", function (): void {
    $policies = app(AuthPolicies::class);
    $policies->setForEnvironment(new AuthPolicy(mfa: MfaRequirement::Optional));

    $org = $this->makeOrganization();
    $policies->setForOrganization($org->id, new AuthPolicy(mfa: MfaRequirement::Required));

    $id = policySubject();
    app(Memberships::class)->add($org->id, $id, MembershipRole::Member);

    expect(app(MfaMandate::class)->requiresEnrolment($id))->toBeTrue();
});

// ---------------------------------------------------------------- lockout

it('never locks out when the policy sets no threshold', function (): void {
    $id = policySubject();
    $attempts = app(LoginAttempts::class);

    foreach (range(1, 20) as $ignored) {
        $attempts->recordFailure($id);
    }

    expect($attempts->isLockedOut($id))->toBeFalse();
});

it('locks the account out at the threshold and lets it back in when the lock expires', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(lockoutThreshold: 3));

    $id = policySubject();
    $attempts = app(LoginAttempts::class);

    expect($attempts->recordFailure($id))->toBeFalse()
        ->and($attempts->recordFailure($id))->toBeFalse()
        ->and($attempts->isLockedOut($id))->toBeFalse();

    // The third crosses it, and says so — the caller may want to tell someone.
    expect($attempts->recordFailure($id))->toBeTrue()
        ->and($attempts->isLockedOut($id))->toBeTrue();

    // A lock that lasts until an administrator intervenes is a denial-of-service tool:
    // anyone who knows an email can lock its owner out at will. It expires on its own.
    $this->travel(16)->minutes();

    expect($attempts->isLockedOut($id))->toBeFalse();
});

it('starts counting again once the window has passed', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(lockoutThreshold: 3));

    $id = policySubject();
    $attempts = app(LoginAttempts::class);

    $attempts->recordFailure($id);
    $attempts->recordFailure($id);

    // Two mistypes a fortnight apart are not an attack in progress.
    $this->travel(16)->minutes();

    expect($attempts->recordFailure($id))->toBeFalse()
        ->and($attempts->isLockedOut($id))->toBeFalse();
});

it('forgets the failures after a successful sign-in', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(lockoutThreshold: 3));

    $id = policySubject();
    $attempts = app(LoginAttempts::class);

    $attempts->recordFailure($id);
    $attempts->recordFailure($id);
    $attempts->clear($id);

    expect($attempts->recordFailure($id))->toBeFalse()
        ->and($attempts->isLockedOut($id))->toBeFalse();
});

it("applies an organization's tighter threshold when the caller names none", function (): void {
    $policies = app(AuthPolicies::class);
    $policies->setForEnvironment(new AuthPolicy(lockoutThreshold: 10));

    $org = $this->makeOrganization();
    $policies->setForOrganization($org->id, new AuthPolicy(lockoutThreshold: 2));

    $id = policySubject();
    app(Memberships::class)->add($org->id, $id, MembershipRole::Member);

    $attempts = app(LoginAttempts::class);
    $attempts->recordFailure($id);

    expect($attempts->recordFailure($id))->toBeTrue()
        ->and($attempts->isLockedOut($id))->toBeTrue();
});

/**
 * EVERY failed sign-in leaves a trace, not only the one that trips the lock.
 *
 * The sole audit entry here used to be `user.locked_out`, written when the counter
 * crossed the threshold. Every failure below it left nothing — and so did every failure
 * on a deployment with no lockout policy at all, because `recordFailure()` returned before
 * reaching the audit.
 *
 * That is exactly backwards for the attack the counter exists to bound. Password spraying
 * is quiet on purpose: three guesses each against five thousand accounts, under a
 * threshold of five, locks nobody out — and produced an audit trail containing literally
 * nothing. The signal that would have shown it (many accounts, few attempts each, one
 * source) was the one never written.
 */
it('audits a failed sign-in that does not reach the lockout threshold', function (): void {
    $subject = app(Subjects::class)->create('sprayed@acme.test', 'Sprayed', 'a-strong-unbreached-passphrase');

    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(lockoutThreshold: 5));

    $locked = app(LoginAttempts::class)->recordFailure($subject->id);

    expect($locked)->toBeFalse('one failure must not lock a threshold of five');

    $entry = AuditEntry::query()->where('action', 'user.sign_in_failed')->latest('id')->first();

    expect($entry)->not->toBeNull('a failure below the threshold left no trace at all')
        ->and($entry->target_id)->toBe($subject->id);
})->group('security');

it('audits a failed sign-in on a deployment with no lockout policy', function (): void {
    // The earlier return: with no policy there is no threshold, so the method used to
    // stop before anything was written. A deployment that has not configured lockout is
    // the one that most needs the trail.
    $subject = app(Subjects::class)->create('nopolicy@acme.test', 'None', 'a-strong-unbreached-passphrase');

    expect(app(LoginAttempts::class)->recordFailure($subject->id))->toBeFalse();

    expect(AuditEntry::query()->where('action', 'user.sign_in_failed')->where('target_id', $subject->id)->exists())
        ->toBeTrue('no lockout policy meant no record of the attempt');
})->group('security');
