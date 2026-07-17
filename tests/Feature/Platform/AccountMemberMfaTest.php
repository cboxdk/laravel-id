<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\Contracts\AccountMemberMfa;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function mfaMemberId(string $email = 'owner@acme.test'): string
{
    return app(AccountProvisioner::class)->provision(new AccountBlueprint(
        accountName: 'Acme',
        ownerEmail: $email,
        ownerName: 'Owner',
        ownerPassword: 'supersecret123',
    ))->member->id;
}

it('enrolls, confirms and verifies an account-member TOTP factor', function (): void {
    $mfa = app(AccountMemberMfa::class);
    $totp = app(TotpAuthenticator::class);
    $id = mfaMemberId();

    $enrollment = $mfa->enrollTotp($id, 'owner@acme.test');

    expect($enrollment->provisioningUri)->toStartWith('otpauth://totp/')
        ->and($mfa->hasConfirmedTotp($id))->toBeFalse();

    expect($mfa->confirmTotp($id, $totp->codeAt($enrollment->secret, time())))->toBeTrue()
        ->and($mfa->hasConfirmedTotp($id))->toBeTrue()
        ->and($mfa->verifyTotp($id, $totp->codeAt($enrollment->secret, time() + 30)))->toBeTrue();
});

it('rejects replay of an account-member TOTP code within its window', function (): void {
    $mfa = app(AccountMemberMfa::class);
    $totp = app(TotpAuthenticator::class);
    $id = mfaMemberId();

    $enrollment = $mfa->enrollTotp($id, 'owner@acme.test');
    $code = $totp->codeAt($enrollment->secret, time());
    $mfa->confirmTotp($id, $code);

    expect($mfa->verifyTotp($id, $code))->toBeFalse();
});

it('keeps account-member and subject MFA factors independent', function (): void {
    $mfa = app(AccountMemberMfa::class);
    $totp = app(TotpAuthenticator::class);
    $id = mfaMemberId();

    $enrollment = $mfa->enrollTotp($id, 'owner@acme.test');
    $mfa->confirmTotp($id, $totp->codeAt($enrollment->secret, time()));

    expect($mfa->hasConfirmedTotp($id))->toBeTrue()
        ->and(app(Mfa::class)->hasConfirmedTotp($id))->toBeFalse();
});

it('generates single-use recovery codes and disables the factor', function (): void {
    $mfa = app(AccountMemberMfa::class);
    $id = mfaMemberId();

    $codes = $mfa->generateRecoveryCodes($id, 5);

    expect($codes)->toHaveCount(5)
        ->and($mfa->remainingRecoveryCodes($id))->toBe(5)
        ->and($mfa->verifyRecoveryCode($id, $codes[0]))->toBeTrue()
        ->and($mfa->verifyRecoveryCode($id, $codes[0]))->toBeFalse()
        ->and($mfa->remainingRecoveryCodes($id))->toBe(4);

    $mfa->disable($id);
    expect($mfa->hasConfirmedTotp($id))->toBeFalse()
        ->and($mfa->remainingRecoveryCodes($id))->toBe(0);
});
