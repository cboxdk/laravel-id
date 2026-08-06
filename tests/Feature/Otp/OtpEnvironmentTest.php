<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Exceptions\EnvironmentMissing;
use Cbox\Id\Otp\Enums\OtpFailureReason;
use Cbox\Id\Otp\Models\OtpChallenge;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @group isolation
 *
 * The OTP challenge is environment-owned, so cross-environment verification is
 * structurally impossible and issuance requires an ambient environment.
 */
it('refuses to issue when no environment is in context', function (): void {
    $this->fakeOtpChannel();
    $this->forgetEnvironment();

    $this->issueOtp('login', 'mallory@example.test');
})->throws(EnvironmentMissing::class);

it('cannot verify a challenge from another environment', function (): void {
    $channel = $this->fakeOtpChannel();

    // Issue inside env_a.
    $challenge = $this->runAsEnvironment('env_a', fn () => $this->issueOtp('login', 'nina@example.test'));
    $code = (string) $channel->codeFor('nina@example.test');

    // The same code, presented in env_b, cannot verify the env_a challenge: the
    // hard environment scope makes it invisible, so it is a uniform Invalid.
    $inB = $this->runAsEnvironment('env_b', fn () => $this->verifyOtp($challenge->id, $code));
    expect($inB->verified)->toBeFalse()
        ->and($inB->reason)->toBe(OtpFailureReason::Invalid);

    // It still verifies in its own environment.
    $inA = $this->runAsEnvironment('env_a', fn () => $this->verifyOtp($challenge->id, $code));
    expect($inA->verified)->toBeTrue();
})->group('isolation');

it('auto-stamps the environment on the challenge row', function (): void {
    $this->fakeOtpChannel();

    $challenge = $this->runAsEnvironment('env_a', fn () => $this->issueOtp('login', 'olivia@example.test'));

    $stored = $this->runAsEnvironment('env_a', fn () => OtpChallenge::query()->whereKey($challenge->id)->firstOrFail());
    expect($stored->environment_id)->toBe('env_a');

    // Invisible from env_b, even by primary key.
    $this->runAsEnvironment('env_b', function () use ($challenge): void {
        expect(OtpChallenge::query()->whereKey($challenge->id)->first())->toBeNull();
    });
})->group('isolation');
