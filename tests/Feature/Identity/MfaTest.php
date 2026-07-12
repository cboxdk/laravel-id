<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Mfa\TotpAuthenticator;
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
        ->and($mfa->hasConfirmedTotp('user_1'))->toBeTrue()
        ->and($mfa->verifyTotp('user_1', $totp->codeAt($enrollment->secret, time())))->toBeTrue();
});

it('rejects a wrong code', function (): void {
    $mfa = app(Mfa::class);
    $mfa->enrollTotp('user_2', 'x@x.test');

    expect($mfa->confirmTotp('user_2', '000000'))->toBeFalse()
        ->and($mfa->hasConfirmedTotp('user_2'))->toBeFalse();
});

it('records an audit entry on enrolment', function (): void {
    $audit = $this->fakeAudit();
    $mfa = app(Mfa::class);
    $totp = app(TotpAuthenticator::class);

    $enrollment = $mfa->enrollTotp('user_3', 'x@x.test');
    $mfa->confirmTotp('user_3', $totp->codeAt($enrollment->secret, time()));

    $audit->assertRecorded('user.mfa_enrolled');
});
