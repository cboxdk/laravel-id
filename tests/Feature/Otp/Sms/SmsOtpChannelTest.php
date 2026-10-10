<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Otp\Channels\SmsOtpChannel;
use Cbox\Id\Otp\Contracts\OtpChannels;
use Cbox\Id\Otp\Sms\Contracts\SmsSendGuard;
use Cbox\Id\Otp\Sms\Exceptions\InvalidPhoneNumber;
use Cbox\Id\Otp\Sms\Exceptions\SmsDeliveryFailed;
use Cbox\Id\Otp\Sms\Exceptions\SmsSendRefused;
use Cbox\Id\Otp\Sms\SmsDispatcher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Cache::flush();
    app(OtpChannels::class)->register('sms', app(SmsOtpChannel::class));
});

it('texts a code through the OTP service that then verifies once', function (): void {
    $sms = $this->fakeSms();

    $challenge = $this->issueOtp('login', '+45 12 34 56 78', 'sms', '203.0.113.9');

    $sms->assertSent('+4512345678');
    $code = (string) $sms->latestCode();

    expect($code)->toMatch('/^\d{6}$/')
        ->and($this->verifyOtp($challenge->id, $code)->verified)->toBeTrue()
        ->and($this->verifyOtp($challenge->id, $code)->verified)->toBeFalse();
});

it('writes the text in the language the request is served in', function (): void {
    $sms = $this->fakeSms();

    app()->setLocale('sv');
    $this->issueOtp('login', '+46701234567', 'sms');

    expect($sms->latest()?->body)->toContain('verifieringskod');
});

it('audits each send with the number masked and never the code', function (): void {
    $sms = $this->fakeSms();

    $challenge = $this->issueOtp('login', '+4512345678', 'sms', '203.0.113.9');
    $code = (string) $sms->latestCode();

    $entry = AuditEntry::query()->where('action', 'sms.sent')->sole();

    expect($entry->target_id)->toBe($challenge->id)
        ->and($entry->context)->toMatchArray([
            'to' => '+45 ******78', 'country' => 'DK', 'purpose' => 'login', 'channel' => 'sms',
            'provider' => 'array', 'message_id' => 'array-1',
        ])
        ->and($entry->ip)->toBe('203.0.113.9')
        ->and(json_encode($entry->context))->not->toContain('12345678')
        ->and(json_encode($entry->context))->not->toContain($code);
});

it('refuses and audits a send the guard declines, before the provider is called', function (): void {
    $sms = $this->fakeSms();
    config()->set('cbox-id.sms.allowed_countries', ['DK']);
    app()->forgetInstance(SmsSendGuard::class);
    app()->forgetInstance(SmsDispatcher::class);
    app(OtpChannels::class)->register('sms', app(SmsOtpChannel::class));

    expect(fn () => $this->issueOtp('login', '+18765550199', 'sms'))->toThrow(SmsSendRefused::class);

    $sms->assertNothingSent();
    expect(AuditEntry::query()->where('action', 'sms.refused')->sole()->context)
        ->toMatchArray(['to' => '+1 ********99', 'country' => 'JM', 'reason' => 'country_not_allowed']);
});

it('audits a provider failure and lets it surface', function (): void {
    $sms = $this->fakeSms();
    $sms->failNext();

    expect(fn () => $this->issueOtp('login', '+4512345678', 'sms'))->toThrow(SmsDeliveryFailed::class);

    expect(AuditEntry::query()->where('action', 'sms.failed')->sole()->context)
        ->toMatchArray(['to' => '+45 ******78', 'provider' => 'array']);
});

it('refuses a recipient that is not a phone number', function (): void {
    $this->fakeSms();

    $this->issueOtp('login', 'alice@example.test', 'sms');
})->throws(InvalidPhoneNumber::class);
