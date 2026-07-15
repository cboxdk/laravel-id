<?php

declare(strict_types=1);

use Cbox\Id\Otp\Contracts\OtpService;
use Cbox\Id\Otp\Enums\OtpFailureReason;
use Cbox\Id\Otp\Exceptions\OtpRateLimitExceeded;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('refuses issuing beyond the per-recipient window', function (): void {
    config()->set('cbox-id.otp.issue.max_per_window', 3);
    app()->forgetInstance(OtpService::class);

    $this->fakeOtpChannel();

    // The first three issues (same recipient + purpose + ip) are allowed.
    for ($i = 0; $i < 3; $i++) {
        $this->issueOtp('login', 'heidi@example.test', 'fake', '203.0.113.7');
    }

    // The fourth is refused.
    $this->issueOtp('login', 'heidi@example.test', 'fake', '203.0.113.7');
})->throws(OtpRateLimitExceeded::class);

it('scopes the issue throttle per recipient', function (): void {
    config()->set('cbox-id.otp.issue.max_per_window', 1);
    app()->forgetInstance(OtpService::class);

    $this->fakeOtpChannel();

    // One each for two different recipients from the same IP is fine — the limit
    // is per recipient, so one recipient cannot exhaust another's budget.
    $this->issueOtp('login', 'ivan@example.test', 'fake', '203.0.113.7');
    $this->issueOtp('login', 'judy@example.test', 'fake', '203.0.113.7');

    expect(true)->toBeTrue();
});

it('caps issuance per recipient across differing purposes and IPs', function (): void {
    // Relax the narrow (recipient+purpose+ip) key so ONLY the broad per-recipient
    // cap can trip — proving it stops an attacker who rotates purpose and IP.
    config()->set('cbox-id.otp.issue.max_per_window', 100);
    config()->set('cbox-id.otp.issue.per_recipient_max', 3);
    app()->forgetInstance(OtpService::class);

    $this->fakeOtpChannel();

    // Three issues to one recipient, each a DIFFERENT purpose AND IP — every one
    // slips past the narrow key, but the per-recipient cap counts them together.
    $this->issueOtp('login', 'olivia@example.test', 'fake', '203.0.113.1');
    $this->issueOtp('signup', 'olivia@example.test', 'fake', '203.0.113.2');
    $this->issueOtp('reset', 'olivia@example.test', 'fake', '203.0.113.3');

    // The fourth — again varying purpose and IP — is still refused.
    $this->issueOtp('mfa', 'olivia@example.test', 'fake', '203.0.113.4');
})->throws(OtpRateLimitExceeded::class);

it('caps verifyLatest per recipient across differing IPs', function (): void {
    // Relax the per-IP key so ONLY the per-recipient verify cap can trip.
    config()->set('cbox-id.otp.verify.max_per_window', 100);
    config()->set('cbox-id.otp.verify.per_recipient_max', 3);
    app()->forgetInstance(OtpService::class);

    $channel = $this->fakeOtpChannel();
    $this->issueOtp('login', 'peggy@example.test');
    $code = (string) $channel->codeFor('peggy@example.test');

    // Three verifyLatest attempts, each from a different source IP, are counted.
    for ($i = 0; $i < 3; $i++) {
        app(OtpService::class)->verifyLatest('login', 'peggy@example.test', '000000', "198.51.100.{$i}");
    }

    // The next — even the correct code from yet another IP — is throttled, so the
    // recipient's live challenge cannot be brute-forced by spraying across IPs.
    $throttled = app(OtpService::class)->verifyLatest('login', 'peggy@example.test', $code, '198.51.100.9');

    expect($throttled->verified)->toBeFalse()
        ->and($throttled->reason)->toBe(OtpFailureReason::RateLimited);
});

it('refuses verification beyond the global per-IP throttle', function (): void {
    config()->set('cbox-id.otp.verify.max_per_window', 3);
    app()->forgetInstance(OtpService::class);

    $channel = $this->fakeOtpChannel();
    $challenge = $this->issueOtp('login', 'ken@example.test');
    $code = (string) $channel->codeFor('ken@example.test');

    $ip = '198.51.100.4';

    // Three brute-force attempts from one IP are counted.
    for ($i = 0; $i < 3; $i++) {
        app(OtpService::class)->verify($challenge->id, '000000', $ip);
    }

    // The next attempt — even with the correct code — is throttled, so a code can
    // never be brute-forced across its 10^6 space within the window.
    $throttled = app(OtpService::class)->verify($challenge->id, $code, $ip);

    expect($throttled->verified)->toBeFalse()
        ->and($throttled->reason)->toBe(OtpFailureReason::RateLimited);
});
