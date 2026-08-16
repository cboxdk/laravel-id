<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

// RFC 6238 test secret: base32 of ASCII "12345678901234567890".
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

it('matches the RFC 6238 test vectors', function (): void {
    $totp = app(TotpAuthenticator::class);

    expect($totp->codeAt(RFC_SECRET, 59))->toBe('287082')
        ->and($totp->codeAt(RFC_SECRET, 1111111109))->toBe('081804')
        ->and($totp->codeAt(RFC_SECRET, 1111111111))->toBe('050471')
        ->and($totp->codeAt(RFC_SECRET, 1234567890))->toBe('005924')
        ->and($totp->codeAt(RFC_SECRET, 2000000000))->toBe('279037');
});

it('tolerates one step of clock skew', function (): void {
    $totp = app(TotpAuthenticator::class);
    $now = 1234567890;

    expect($totp->verify(RFC_SECRET, $totp->codeAt(RFC_SECRET, $now - 30), $now))->toBeTrue()
        ->and($totp->verify(RFC_SECRET, $totp->codeAt(RFC_SECRET, $now - 90), $now))->toBeFalse();
});

it('enrolls, confirms and then verifies a TOTP factor', function (): void {
    $mfa = app(Mfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('user_1', 'ida@northwind.test');
    expect($enrollment->provisioningUri)->toStartWith('otpauth://totp/')
        ->and($mfa->hasConfirmedTotp('user_1'))->toBeFalse()          // unconfirmed until proven
        ->and($mfa->verifyTotp('user_1', $totp->codeAt($enrollment->secret, time())))->toBeFalse();

    expect($mfa->confirmTotp('user_1', $totp->codeAt($enrollment->secret, time())))->toBeTrue()
        ->and($mfa->hasConfirmedTotp('user_1'))->toBeTrue();
});

it('rejects reuse of a TOTP code within its validity window (replay)', function (): void {
    $mfa = app(Mfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('user_replay', 'r@r.test');
    $code = $totp->codeAt($enrollment->secret, time());

    // First presentation confirms the factor and consumes this time step.
    expect($mfa->confirmTotp('user_replay', $code))->toBeTrue();

    // The same code — still valid on the clock — must not verify a second time.
    expect($mfa->verifyTotp('user_replay', $code))->toBeFalse();
});

it('accepts a fresh TOTP code at a later step after one was consumed', function (): void {
    $mfa = app(Mfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('user_step', 's@s.test');

    // Confirm with the previous step's code (within the ±1 skew window), which
    // seeds last_used_step one step back, then verify with the current code (a
    // strictly later step) — proving the guard rejects only replays, not new codes.
    expect($mfa->confirmTotp('user_step', $totp->codeAt($enrollment->secret, time() - 30)))->toBeTrue()
        ->and($mfa->verifyTotp('user_step', $totp->codeAt($enrollment->secret, time())))->toBeTrue();
});

it('rejects a wrong code', function (): void {
    $mfa = app(Mfa::class);
    $mfa->enrollTotp('user_2', 'x@x.test');

    expect($mfa->confirmTotp('user_2', '000000'))->toBeFalse()
        ->and($mfa->hasConfirmedTotp('user_2'))->toBeFalse();
});

it('generates one-time recovery codes and consumes each once', function (): void {
    $mfa = app(Mfa::class);

    $codes = $mfa->generateRecoveryCodes('user_rc', 8);

    expect($codes)->toHaveCount(8)
        ->and($mfa->remainingRecoveryCodes('user_rc'))->toBe(8);

    // A valid code works exactly once.
    expect($mfa->verifyRecoveryCode('user_rc', $codes[0]))->toBeTrue()
        ->and($mfa->verifyRecoveryCode('user_rc', $codes[0]))->toBeFalse() // reuse rejected
        ->and($mfa->remainingRecoveryCodes('user_rc'))->toBe(7);

    // Formatting/casing is cosmetic — a code still matches without its hyphen.
    expect($mfa->verifyRecoveryCode('user_rc', strtoupper(str_replace('-', '', $codes[1]))))->toBeTrue();
});

it('regenerating recovery codes invalidates the previous set', function (): void {
    $mfa = app(Mfa::class);

    $old = $mfa->generateRecoveryCodes('user_rg', 5);
    $mfa->generateRecoveryCodes('user_rg', 5); // replaces

    expect($mfa->verifyRecoveryCode('user_rg', $old[0]))->toBeFalse()
        ->and($mfa->remainingRecoveryCodes('user_rg'))->toBe(5);
});

it('rejects an unknown recovery code', function (): void {
    $mfa = app(Mfa::class);
    $mfa->generateRecoveryCodes('user_x', 3);

    expect($mfa->verifyRecoveryCode('user_x', 'not-a-real-code'))->toBeFalse();
});

it('records an audit entry on enrolment', function (): void {
    $audit = $this->fakeAudit();
    $mfa = app(Mfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('user_3', 'x@x.test');
    $mfa->confirmTotp('user_3', $totp->codeAt($enrollment->secret, time()));

    $audit->assertRecorded('user.mfa_enrolled');
});

/**
 * A recovery code is spent exactly once.
 *
 * TOTP single-use is already covered above; the recovery path was not. Both now claim
 * their credential with a conditional UPDATE rather than a read-then-write, so two
 * requests presenting the same code concurrently cannot both be admitted.
 */
it('spends a recovery code exactly once even when presented twice', function (): void {
    $userId = 'user_recovery_race';
    $mfa = app(Mfa::class);
    $codes = $mfa->generateRecoveryCodes($userId, 3);

    expect($mfa->verifyRecoveryCode($userId, $codes[0]))->toBeTrue()
        ->and($mfa->verifyRecoveryCode($userId, $codes[0]))->toBeFalse()
        // The other codes are untouched by the refused replay.
        ->and($mfa->verifyRecoveryCode($userId, $codes[1]))->toBeTrue();
});

/**
 * An administrator has to be able to help someone who has lost their authenticator —
 * and that is the single most privileged MFA mutation in the platform, so it is the one
 * that most needs a trail.
 *
 * There was no `disable()` on this contract, so the host console did it with raw model
 * deletes: no audit entry, no domain event, nothing. Every OTHER MFA mutation here is
 * audited, and the account and operator planes have had the verb from the start — so an
 * access review, a SIEM stream and a compliance export all showed that nothing happened.
 */
it('removes every factor and recovery code, and says so in the audit trail', function (): void {
    $mfa = app(Mfa::class);
    $user = app(Subjects::class)->create('lost-phone@acme.test', 'Lost Phone', 'super-secret-1234');

    $enrollment = $mfa->enrollTotp($user->id, $user->email);
    $mfa->confirmTotp($user->id, app(TotpAuthenticator::class)->codeAt($enrollment->secret, time()));
    $mfa->generateRecoveryCodes($user->id, 5);

    expect($mfa->hasConfirmedTotp($user->id))->toBeTrue()
        ->and($mfa->remainingRecoveryCodes($user->id))->toBe(5);

    $mfa->disable($user->id);

    expect($mfa->hasConfirmedTotp($user->id))->toBeFalse()
        ->and($mfa->remainingRecoveryCodes($user->id))->toBe(0);

    expect(AuditEntry::query()->where('action', 'user.mfa_disabled')->where('target_id', $user->id)->exists())
        ->toBeTrue('disabling a second factor left no audit entry');
});

/**
 * The loser of a genuine race gets nothing — the same property the operator plane holds,
 * on the plane where every ordinary user's second factor lives.
 *
 * `MfaService::verifyTotp()` advances the step with a conditional UPDATE and returns
 * `$advanced === 1`, so two requests presenting the SAME intercepted code cannot both
 * succeed: both pass the in-PHP replay check, because both read the factor before either
 * writes, and only the atomic update separates them. Nothing here asserted that. The
 * sibling test on the operator plane appeared to, and did not — it built the conditional
 * update in the test and asserted the DATABASE honoured a WHERE clause, which was never
 * in doubt. Replacing production's update with a plain one left every MFA test on both
 * planes green.
 *
 * The seam is the authenticator: `matchStep()` runs after production has read the factor
 * and before it writes, so advancing the row there puts production in exactly the state
 * the losing request is in.
 */
it('refuses the step when another request advanced it between the read and the write', function (): void {
    $mfa = app(Mfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('user_race', 'race@corp.test');
    $mfa->confirmTotp('user_race', $totp->codeAt($enrollment->secret, time()));

    $step = intdiv(time() + 30, 30);
    $code = $totp->codeAt($enrollment->secret, time() + 30);

    app()->instance(TotpAuthenticator::class, new class($totp, $step) extends TotpAuthenticator
    {
        public function __construct(private readonly TotpAuthenticator $inner, private readonly int $step) {}

        public function matchStep(string $base32Secret, string $code, ?int $timestamp = null, int $window = 1): ?int
        {
            $matched = $this->inner->matchStep($base32Secret, $code, $timestamp, $window);

            // The concurrent winner, committing inside production's read-write gap.
            MfaFactor::query()->where('user_id', 'user_race')->update(['last_used_step' => $this->step]);

            return $matched;
        }
    });

    app()->forgetInstance(Mfa::class);

    expect(app(Mfa::class)->verifyTotp('user_race', $code))
        ->toBeFalse('a second request claimed a step another had already consumed');
});
