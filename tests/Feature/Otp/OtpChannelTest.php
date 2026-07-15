<?php

declare(strict_types=1);

use Cbox\Id\Otp\Channels\EmailOtpChannel;
use Cbox\Id\Otp\Contracts\OtpChannels;
use Cbox\Id\Otp\Exceptions\UnknownOtpChannel;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;
use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('refuses an unregistered channel key (deny-by-default)', function (): void {
    // No sender is registered for `sms` in the default config — issuing is refused,
    // never a silent no-op.
    $this->issueOtp('login', '+15550000000', 'sms');
})->throws(UnknownOtpChannel::class);

it('registers the email channel by default and refuses unknown keys', function (): void {
    $registry = app(OtpChannels::class);

    expect($registry->has('email'))->toBeTrue()
        ->and($registry->has('sms'))->toBeFalse()
        ->and($registry->channel('email'))->toBeInstanceOf(EmailOtpChannel::class);

    expect(fn () => $registry->channel('nope'))->toThrow(UnknownOtpChannel::class);
});

it('email channel puts the code in a plain-text message over the mailer', function (): void {
    $captured = null;

    $mailer = Mockery::mock(Mailer::class);
    $mailer->shouldReceive('raw')->once()
        ->with(Mockery::on(function (string $body) use (&$captured): bool {
            $captured = $body;

            return true;
        }), Mockery::type(Closure::class));

    $channel = new EmailOtpChannel($mailer);

    $channel->deliver(new OtpDelivery(
        challengeId: '01OTP',
        recipient: 'liam@example.test',
        code: '135790',
        purpose: 'login',
        channel: 'email',
        expiresAt: new DateTimeImmutable('+5 minutes'),
        ttlSeconds: 300,
    ));

    expect($captured)->toContain('135790')
        ->and($captured)->toContain('5 minute');
});
