<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Platform\Contracts\OperatorMfa;
use Cbox\Id\Platform\Models\OperatorMfaFactor;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('enrolls, confirms and verifies an operator TOTP factor', function (): void {
    $mfa = app(OperatorMfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('op_1', 'root@platform.test');

    expect($enrollment->provisioningUri)->toStartWith('otpauth://totp/')
        ->and($mfa->hasConfirmedTotp('op_1'))->toBeFalse()                        // unconfirmed until proven
        ->and($mfa->verifyTotp('op_1', $totp->codeAt($enrollment->secret, time())))->toBeFalse();

    expect($mfa->confirmTotp('op_1', $totp->codeAt($enrollment->secret, time())))->toBeTrue()
        ->and($mfa->hasConfirmedTotp('op_1'))->toBeTrue()
        // A code from a later step (not the one just consumed on confirm) verifies.
        ->and($mfa->verifyTotp('op_1', $totp->codeAt($enrollment->secret, time() + 30)))->toBeTrue();
});

it('rejects replay of an operator TOTP code within its window', function (): void {
    $mfa = app(OperatorMfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('op_1', 'root@platform.test');
    $code = $totp->codeAt($enrollment->secret, time());
    $mfa->confirmTotp('op_1', $code);

    // The confirming code was already accepted; the same code cannot be reused.
    expect($mfa->verifyTotp('op_1', $code))->toBeFalse();
});

it('keeps operator and subject MFA factors independent', function (): void {
    $mfa = app(OperatorMfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('shared_id', 'root@platform.test');
    $mfa->confirmTotp('shared_id', $totp->codeAt($enrollment->secret, time()));

    // A subject with the same id has no operator factor bleed and vice versa.
    expect($mfa->hasConfirmedTotp('shared_id'))->toBeTrue()
        ->and(app(Mfa::class)->hasConfirmedTotp('shared_id'))->toBeFalse();
});

it('generates single-use operator recovery codes', function (): void {
    $mfa = app(OperatorMfa::class);

    $codes = $mfa->generateRecoveryCodes('op_1', 5);

    expect($codes)->toHaveCount(5)
        ->and($mfa->remainingRecoveryCodes('op_1'))->toBe(5)
        ->and($mfa->verifyRecoveryCode('op_1', $codes[0]))->toBeTrue()
        ->and($mfa->verifyRecoveryCode('op_1', $codes[0]))->toBeFalse()   // single use
        ->and($mfa->remainingRecoveryCodes('op_1'))->toBe(4)
        ->and($mfa->verifyRecoveryCode('op_1', 'not-a-real-code'))->toBeFalse();
});

it('disables an operator factor and its recovery codes', function (): void {
    $mfa = app(OperatorMfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('op_1', 'root@platform.test');
    $mfa->confirmTotp('op_1', $totp->codeAt($enrollment->secret, time()));
    $mfa->generateRecoveryCodes('op_1', 3);

    $mfa->disable('op_1');

    expect($mfa->hasConfirmedTotp('op_1'))->toBeFalse()
        ->and($mfa->remainingRecoveryCodes('op_1'))->toBe(0);
});

/**
 * One code, one sign-in — under a RACE, not just in sequence.
 *
 * The sequential case was already covered: verify twice and the replay check rejects the
 * second, because by then the stored step has advanced. The race is different. Two
 * requests presenting the same intercepted code at the same instant both pass that check
 * — they both read the old step — and a plain read-then-write lets both through. The
 * subject plane has consumed codes with a conditional UPDATE from the start, with a
 * comment saying exactly this; the operator and account-member planes did the
 * read-then-write, on the two planes where it matters most, while this class's own
 * docblock claimed they could not drift on the security-relevant parts.
 *
 * Threads are not available here, so this asserts the MECHANISM the fix rests on: once a
 * step is recorded, an update conditioned on the earlier step affects zero rows. That is
 * the whole reason the losing request in a real race cannot proceed.
 */
it('consumes a TOTP step with an update that a concurrent duplicate cannot win', function (): void {
    $mfa = app(OperatorMfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('op_race', 'race@platform.test');
    $mfa->confirmTotp('op_race', $totp->codeAt($enrollment->secret, time()));

    $step = intdiv(time() + 30, 30);
    expect($mfa->verifyTotp('op_race', $totp->codeAt($enrollment->secret, time() + 30)))->toBeTrue();

    $factor = OperatorMfaFactor::query()->where('operator_id', 'op_race')->firstOrFail();
    expect($factor->last_used_step)->toBe($step);

    // The write the loser of the race would attempt: same step, conditioned on the state
    // it read before the winner committed. Zero rows, so it cannot claim the code.
    $claimed = OperatorMfaFactor::query()
        ->whereKey($factor->id)
        ->where(fn ($query) => $query->whereNull('last_used_step')->orWhere('last_used_step', '<', $step))
        ->update(['last_used_step' => $step]);

    expect($claimed)->toBe(0, 'a second request could claim a step already consumed');

    // And the ordinary sequential replay is still refused.
    expect($mfa->verifyTotp('op_race', $totp->codeAt($enrollment->secret, time() + 30)))->toBeFalse();
});
