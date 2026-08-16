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
/**
 * The loser of a genuine race gets nothing — asserted through PRODUCTION's write.
 *
 * The version this replaces built the conditional UPDATE in the test and asserted it
 * affected zero rows. That is the test's own SQL: it proves the database honours a WHERE
 * clause, which was never in doubt, and says nothing about whether
 * `DatabaseOperatorMfa::verifyTotp()` still uses one. Verified — replacing production's
 * conditional update with a plain `update()` and `return true` left all six tests in this
 * file green, including the one named after the race.
 *
 * Two requests presenting the SAME intercepted code both pass the in-PHP replay check,
 * because both read the factor before either writes. Only the atomic update separates
 * them, and on the operator plane one code admitting two sign-ins is the worst place for
 * it. So the interleaving is what has to be reproduced.
 *
 * The seam is the authenticator: `matchStep()` is called AFTER production has read the
 * factor and BEFORE it writes, so a decorator that advances the row there puts production
 * in exactly the state the losing request is in — holding a stale `last_used_step` and
 * about to attempt a write another request has already made.
 */
it('refuses the step when another request advanced it between the read and the write', function (): void {
    $mfa = app(OperatorMfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('op_race', 'race@platform.test');
    $mfa->confirmTotp('op_race', $totp->codeAt($enrollment->secret, time()));

    $step = intdiv(time() + 30, 30);
    $code = $totp->codeAt($enrollment->secret, time() + 30);

    // The concurrent winner, committing inside production's own read-write gap.
    app()->instance(TotpAuthenticator::class, new class($totp, $step) extends TotpAuthenticator
    {
        public function __construct(private readonly TotpAuthenticator $inner, private readonly int $step) {}

        public function matchStep(string $base32Secret, string $code, ?int $timestamp = null, int $window = 1): ?int
        {
            $matched = $this->inner->matchStep($base32Secret, $code, $timestamp, $window);

            OperatorMfaFactor::query()
                ->where('operator_id', 'op_race')
                ->update(['last_used_step' => $this->step]);

            return $matched;
        }
    });

    // Resolved fresh so it takes the decorated authenticator.
    app()->forgetInstance(OperatorMfa::class);

    expect(app(OperatorMfa::class)->verifyTotp('op_race', $code))
        ->toBeFalse('a second request claimed a step another had already consumed');
});
