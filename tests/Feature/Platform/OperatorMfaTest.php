<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Platform\Contracts\OperatorMfa;
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
