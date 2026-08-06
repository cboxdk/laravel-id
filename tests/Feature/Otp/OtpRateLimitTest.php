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

/**
 * A rate limit one tenant can spend on another tenant's behalf is not a rate limit.
 *
 * Every key in this class was built from purpose, recipient and IP against the shared
 * application cache — no environment. So an attacker on their own free-trial environment
 * could call `verifyLatest('login', 'victim@corp.example', '000000')` until the budget
 * was gone, and the victim, on an entirely unrelated tenant, could not use a one-time
 * code to sign in for the rest of the window. Re-sprayed every fifteen minutes, that is
 * indefinite.
 *
 * The issuance budget is the same defect facing the other way: burn it and the victim's
 * OWN tenant is stopped from sending them a code for an hour.
 *
 * Sharing a key is only the more restrictive choice when the thing being bounded is
 * guessing. These budgets also bound delivery, and there the sharing is the attack.
 */
it('does not let one environment spend another environment issue budget', function (): void {
    config()->set('cbox-id.otp.issue.max_per_window', 1);
    config()->set('cbox-id.otp.issue.per_recipient_max', 1);
    app()->forgetInstance(OtpService::class);

    $this->fakeOtpChannel();

    $this->runAsEnvironment('env_a', fn () => $this->issueOtp('login', 'shared@example.test', 'fake', '203.0.113.9'));

    // The same recipient, on a different tenant, still has their own budget.
    $inB = $this->runAsEnvironment(
        'env_b',
        fn () => $this->issueOtp('login', 'shared@example.test', 'fake', '203.0.113.9'),
    );

    expect($inB->id)->not->toBeEmpty('one environment exhausted another environment issue budget');
});

it('does not let one environment spend another environment verify budget', function (): void {
    config()->set('cbox-id.otp.verify.per_recipient_max', 1);
    app()->forgetInstance(OtpService::class);

    $this->fakeOtpChannel();

    $this->runAsEnvironment('env_a', function (): void {
        $this->issueOtp('login', 'grind@example.test', 'fake', '203.0.113.9');
        // Spend env A's per-recipient verify budget on a wrong code.
        app(OtpService::class)->verifyLatest('login', 'grind@example.test', '000000', '203.0.113.9');
    });

    $outcome = $this->runAsEnvironment('env_b', function () {
        $this->issueOtp('login', 'grind@example.test', 'fake', '203.0.113.9');

        // A wrong code here too: the assertion is about WHY it is refused, not whether.
        // A rate-limited answer means env A spent env B's budget.
        return app(OtpService::class)->verifyLatest('login', 'grind@example.test', '111111', '203.0.113.9');
    });

    expect($outcome->reason)
        ->not->toBe(OtpFailureReason::RateLimited, 'one environment locked another out of OTP sign-in');
});
