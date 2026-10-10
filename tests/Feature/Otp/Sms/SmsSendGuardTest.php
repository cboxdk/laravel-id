<?php

declare(strict_types=1);

use Cbox\Id\Otp\Sms\Contracts\SmsSendGuard;
use Cbox\Id\Otp\Sms\Enums\SmsRefusalReason;
use Cbox\Id\Otp\Sms\Exceptions\SmsSendRefused;
use Cbox\Id\Otp\Sms\PhoneNumberNormaliser;
use Cbox\Id\Otp\Sms\RateLimitedSmsSendGuard;
use Cbox\Id\Otp\Sms\ValueObjects\PhoneNumber;
use Illuminate\Cache\RateLimiter;
use Illuminate\Support\Facades\Cache;

function phone(string $number): PhoneNumber
{
    return (new PhoneNumberNormaliser)->parse($number);
}

/**
 * @param  list<string>  $countries
 */
function smsGuard(array $countries = [], int $cooldown = 0, int $perNumber = 0, int $perIp = 0, int $perEnvironment = 0, int $daily = 0): RateLimitedSmsSendGuard
{
    return new RateLimitedSmsSendGuard(app(RateLimiter::class), $countries, $cooldown, $perNumber, $perIp, $perEnvironment, $daily);
}

function refusal(Closure $send): ?SmsRefusalReason
{
    try {
        $send();

        return null;
    } catch (SmsSendRefused $e) {
        return $e->reason;
    }
}

beforeEach(fn () => Cache::flush());

it('refuses a country outside the deployment allow-list, and one outside the caller\'s narrower list', function (): void {
    $guard = smsGuard(['DK', 'SE']);

    expect(refusal(fn () => $guard->admit(phone('+4512345678'))))->toBeNull()
        ->and(refusal(fn () => $guard->admit(phone('+18765550199'))))->toBe(SmsRefusalReason::CountryNotAllowed)
        ->and(refusal(fn () => $guard->admit(phone('+46701234567'), null, ['DK'])))->toBe(SmsRefusalReason::CountryNotAllowed)
        ->and(refusal(fn () => $guard->admit(phone('+4512345678'), null, [])))->toBe(SmsRefusalReason::CountryNotAllowed);

    // An empty deployment list leaves the decision to the caller's list.
    expect(refusal(fn () => smsGuard()->admit(phone('+18765550199'))))->toBeNull()
        ->and(refusal(fn () => smsGuard()->admit(phone('+18765550199'), null, ['US'])))->toBe(SmsRefusalReason::CountryNotAllowed);
});

it('holds one number to one text per cooldown, with the wait reported', function (): void {
    $guard = smsGuard(cooldown: 30);

    $guard->admit(phone('+4512345678'));

    try {
        $guard->admit(phone('+45 12 34 56 78'));
        $this->fail('Expected a cooldown.');
    } catch (SmsSendRefused $e) {
        expect($e->reason)->toBe(SmsRefusalReason::Cooldown)
            ->and($e->retryAfterSeconds)->toBeGreaterThan(0)
            ->and($e->reason->isTemporary())->toBeTrue();
    }

    // Another number is unaffected.
    $guard->admit(phone('+4587654321'));

    $this->travel(31)->seconds();
    $guard->admit(phone('+4512345678'));
});

it('caps texts per number per day', function (): void {
    $guard = smsGuard(perNumber: 2);

    $guard->admit(phone('+4512345678'));
    $guard->admit(phone('+4512345678'));

    expect(refusal(fn () => $guard->admit(phone('+4512345678'))))->toBe(SmsRefusalReason::NumberLimit);
});

it('caps texts per requesting IP, across numbers', function (): void {
    $guard = smsGuard(perIp: 2);

    $guard->admit(phone('+4511111111'), '203.0.113.9');
    $guard->admit(phone('+4522222222'), '203.0.113.9');

    expect(refusal(fn () => $guard->admit(phone('+4533333333'), '203.0.113.9')))->toBe(SmsRefusalReason::IpLimit)
        ->and(refusal(fn () => $guard->admit(phone('+4533333333'), '198.51.100.7')))->toBeNull();
});

it('caps one environment without spending the others', function (): void {
    $guard = smsGuard(perEnvironment: 1);

    $this->runAsEnvironment('env_a', fn () => $guard->admit(phone('+4511111111')));

    expect(refusal(fn () => $this->runAsEnvironment('env_a', fn () => $guard->admit(phone('+4522222222')))))->toBe(SmsRefusalReason::EnvironmentCap)
        ->and(refusal(fn () => $this->runAsEnvironment('env_b', fn () => $guard->admit(phone('+4522222222')))))->toBeNull();
});

it('trips the deployment-wide daily circuit breaker across environments', function (): void {
    $guard = smsGuard(daily: 2);

    $this->runAsEnvironment('env_a', fn () => $guard->admit(phone('+4511111111')));
    $this->runAsEnvironment('env_b', fn () => $guard->admit(phone('+4522222222')));

    expect(refusal(fn () => $this->runAsEnvironment('env_c', fn () => $guard->admit(phone('+4533333333')))))->toBe(SmsRefusalReason::DailyCap);
});

it('counts nothing when it refuses, so a refusal never spends another budget', function (): void {
    $guard = smsGuard(cooldown: 30, perIp: 1);

    $guard->admit(phone('+4511111111'), '203.0.113.9');

    // Refused on the cooldown — the IP budget it would also have charged stays untouched…
    expect(refusal(fn () => $guard->admit(phone('+4511111111'), '198.51.100.7')))->toBe(SmsRefusalReason::Cooldown);

    // …so that address can still send once.
    expect(refusal(fn () => $guard->admit(phone('+4522222222'), '198.51.100.7')))->toBeNull();
});

it('reads its limits from config', function (): void {
    config()->set('cbox-id.sms.allowed_countries', ['dk']);
    config()->set('cbox-id.sms.limits.cooldown_seconds', 0);
    config()->set('cbox-id.sms.limits.per_number_per_day', 1);
    app()->forgetInstance(SmsSendGuard::class);

    $guard = app(SmsSendGuard::class);

    expect(refusal(fn () => $guard->admit(phone('+46701234567'))))->toBe(SmsRefusalReason::CountryNotAllowed);
    $guard->admit(phone('+4512345678'));
    expect(refusal(fn () => $guard->admit(phone('+4512345678'))))->toBe(SmsRefusalReason::NumberLimit);
});
