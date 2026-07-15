<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Testing;

use Cbox\Id\Otp\Contracts\OtpChannels;
use Cbox\Id\Otp\Contracts\OtpService;
use Cbox\Id\Otp\ValueObjects\OtpChallenge;
use Cbox\Id\Otp\ValueObjects\OtpResult;

/**
 * Drop-in test ergonomics for OTP flows, shipped with the package so downstream
 * consumers get the same fluency:
 *
 *     use Cbox\Id\Otp\Testing\InteractsWithOtp;
 *
 *     uses(InteractsWithOtp::class);
 *
 *     it('signs in with an emailed code', function () {
 *         $channel = $this->fakeOtpChannel();
 *         $challenge = $this->issueOtp('login', 'alice@example.test');
 *         $result = $this->verifyOtp($challenge->id, $channel->codeFor());
 *         expect($result->verified)->toBeTrue();
 *     });
 */
trait InteractsWithOtp
{
    /**
     * Register a {@see FakeOtpChannel} under `$key` (default `fake`) and return it,
     * so a test can read back delivered codes.
     */
    protected function fakeOtpChannel(string $key = 'fake'): FakeOtpChannel
    {
        $channel = new FakeOtpChannel;

        app(OtpChannels::class)->register($key, $channel);

        return $channel;
    }

    protected function issueOtp(string $purpose, string $recipient, string $channel = 'fake', ?string $ip = null): OtpChallenge
    {
        return app(OtpService::class)->issue($purpose, $recipient, $channel, $ip);
    }

    protected function verifyOtp(string $challengeId, string $code, ?string $ip = null): OtpResult
    {
        return app(OtpService::class)->verify($challengeId, $code, $ip);
    }
}
