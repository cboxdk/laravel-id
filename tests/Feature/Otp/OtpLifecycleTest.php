<?php

declare(strict_types=1);

use Cbox\Id\Otp\Contracts\OtpService;
use Cbox\Id\Otp\Enums\OtpFailureReason;
use Cbox\Id\Otp\Models\OtpChallenge;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('issues a code to the channel and verifies it exactly once', function (): void {
    $channel = $this->fakeOtpChannel();

    $challenge = $this->issueOtp('login', 'alice@example.test');
    $code = $channel->codeFor('alice@example.test');

    expect($code)->not->toBeNull()
        ->and($code)->toMatch('/^\d{6}$/');

    // First verify with the correct code succeeds.
    $first = $this->verifyOtp($challenge->id, (string) $code);
    expect($first->verified)->toBeTrue()
        ->and($first->reason)->toBe(OtpFailureReason::None);

    // Single-use: a second verify of the same code fails.
    $second = $this->verifyOtp($challenge->id, (string) $code);
    expect($second->verified)->toBeFalse()
        ->and($second->reason)->toBe(OtpFailureReason::Invalid);
});

it('verifies the latest live challenge by recipient + purpose', function (): void {
    $channel = $this->fakeOtpChannel();

    $this->issueOtp('login', 'bob@example.test');
    $code = $channel->codeFor('bob@example.test');

    $result = app(OtpService::class)
        ->verifyLatest('login', 'bob@example.test', (string) $code);

    expect($result->verified)->toBeTrue();
});

it('verifyLatest skips a locked newer challenge and redeems an older live one', function (): void {
    $channel = $this->fakeOtpChannel();

    // Older challenge A — still live.
    $a = $this->issueOtp('login', 'mallory@example.test');
    $codeA = null;
    foreach ($channel->deliveries as $delivery) {
        if ($delivery->challengeId === $a->id) {
            $codeA = $delivery->code;
        }
    }

    // Newer challenge B, which an attacker then locks with wrong guesses.
    $b = $this->issueOtp('login', 'mallory@example.test');
    for ($i = 0; $i < 5; $i++) {
        app(OtpService::class)->verify($b->id, '000000');
    }
    expect(OtpChallenge::query()->whereKey($b->id)->firstOrFail()->isLocked())->toBeTrue();

    // verifyLatest must skip the locked newest B and redeem the older, still-live A,
    // so an attacker cannot shadow a valid code by locking a fresher challenge.
    $result = app(OtpService::class)->verifyLatest('login', 'mallory@example.test', (string) $codeA);
    expect($result->verified)->toBeTrue();
});

it('verifyLatest reports a uniform invalid (no expired oracle) when the only challenge is expired', function (): void {
    $channel = $this->fakeOtpChannel();
    $challenge = $this->issueOtp('login', 'niaj@example.test');
    $code = (string) $channel->codeFor('niaj@example.test');

    OtpChallenge::query()->whereKey($challenge->id)->firstOrFail()
        ->forceFill(['expires_at' => now()->subMinute()])->save();

    // On the recipient path an expired latest challenge is skipped by the finder, so
    // even the correct code returns a uniform Invalid — never a distinguishing Expired.
    $result = app(OtpService::class)->verifyLatest('login', 'niaj@example.test', $code);

    expect($result->verified)->toBeFalse()
        ->and($result->reason)->toBe(OtpFailureReason::Invalid);
});

it('floors a sub-six-digit code length to six', function (): void {
    config()->set('cbox-id.otp.code_length', 4);
    app()->forgetInstance(OtpService::class);

    $channel = $this->fakeOtpChannel();
    $this->issueOtp('login', 'quinn@example.test');

    // A 4-digit config is clamped up to the 6-digit floor; a 10^4 space is refused.
    expect($channel->codeFor('quinn@example.test'))->toMatch('/^\d{6}$/');
});

it('fails a code past its TTL', function (): void {
    $channel = $this->fakeOtpChannel();
    $challenge = $this->issueOtp('login', 'carol@example.test');
    $code = (string) $channel->codeFor('carol@example.test');

    // Push the stored challenge past expiry.
    OtpChallenge::query()->whereKey($challenge->id)->firstOrFail()
        ->forceFill(['expires_at' => now()->subMinute()])->save();

    $result = $this->verifyOtp($challenge->id, $code);

    expect($result->verified)->toBeFalse()
        ->and($result->reason)->toBe(OtpFailureReason::Expired);
});

it('increments attempts on a wrong code and locks after the cap', function (): void {
    $channel = $this->fakeOtpChannel();
    $challenge = $this->issueOtp('login', 'dave@example.test');
    $correct = (string) $channel->codeFor('dave@example.test');

    // Five wrong codes exhaust the default cap of 5 attempts.
    for ($i = 0; $i < 5; $i++) {
        expect($this->verifyOtp($challenge->id, '000000')->reason)->toBe(OtpFailureReason::Invalid);
    }

    $stored = OtpChallenge::query()->whereKey($challenge->id)->firstOrFail();
    expect($stored->attempts)->toBe(5)
        ->and($stored->isLocked())->toBeTrue();

    // Even the CORRECT code fails once the challenge is locked.
    $afterLock = $this->verifyOtp($challenge->id, $correct);
    expect($afterLock->verified)->toBeFalse()
        ->and($afterLock->reason)->toBe(OtpFailureReason::Locked);
});

it('treats an unknown challenge id exactly like a wrong code (no oracle)', function (): void {
    $this->fakeOtpChannel();

    $miss = $this->verifyOtp('01OTPNONEXISTENT00000000000', '123456');
    $wrong = (function () {
        $challenge = $this->issueOtp('login', 'erin@example.test');

        return $this->verifyOtp($challenge->id, '000000');
    })();

    // Both a nonexistent challenge and a wrong code return the same uniform result.
    expect($miss->verified)->toBeFalse()
        ->and($miss->reason)->toBe(OtpFailureReason::Invalid)
        ->and($wrong->verified)->toBeFalse()
        ->and($wrong->reason)->toBe(OtpFailureReason::Invalid);
});
