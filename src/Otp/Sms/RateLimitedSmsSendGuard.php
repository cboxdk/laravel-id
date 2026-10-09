<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms;

use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\Otp\Sms\Contracts\SmsSendGuard;
use Cbox\Id\Otp\Sms\Enums\SmsRefusalReason;
use Cbox\Id\Otp\Sms\Exceptions\SmsSendRefused;
use Cbox\Id\Otp\Sms\ValueObjects\PhoneNumber;
use Illuminate\Cache\RateLimiter;

/**
 * The default {@see SmsSendGuard}, on Laravel's {@see RateLimiter} (so on the cache store —
 * which must be SHARED between replicas, or every replica has its own budget).
 *
 * Checked in order, cheapest and most specific first; nothing is counted until every
 * check has passed, so a refusal never spends another budget:
 *
 *  1. COUNTRY — the deployment's `cbox-id.sms.allowed_countries` (empty: no deployment
 *     restriction) and the caller's narrower list (an environment's policy). Both must
 *     admit the number. Permanent: `country_not_allowed`.
 *  2. COOLDOWN — one text per number per `cooldown_seconds`, per environment.
 *  3. PER NUMBER — `per_number_per_day` texts per number per day, per environment.
 *  4. PER IP — `per_ip_per_hour` texts per requesting address, per environment.
 *  5. ENVIRONMENT CAP — `per_environment_per_day`, so one tenant (or one attacker on a
 *     free trial) cannot spend the whole deployment's budget and lock everybody else out.
 *  6. DAILY CAP — `daily_cap` for the whole deployment: the circuit breaker that bounds
 *     the worst day's bill however every other control was evaded. Deliberately NOT per
 *     environment — it is the operator's ceiling. Set it well above a normal day.
 *
 * Every key but the deployment cap is prefixed with the environment for the reason
 * `DatabaseOtpService` gives: a budget shared across tenants is a budget an attacker on
 * their own tenant can spend on a victim's.
 */
class RateLimitedSmsSendGuard implements SmsSendGuard
{
    use ResolvesEnvironment;

    private const DAY = 86400;

    /**
     * @param  list<string>  $deploymentCountries  upper-case ISO codes; empty = no deployment-level restriction
     */
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly array $deploymentCountries = [],
        private readonly int $cooldownSeconds = 30,
        private readonly int $perNumberPerDay = 10,
        private readonly int $perIpPerHour = 10,
        private readonly int $perEnvironmentPerDay = 1000,
        private readonly int $dailyCap = 5000,
    ) {}

    public function admit(PhoneNumber $to, ?string $ip = null, ?array $allowedCountries = null): void
    {
        if (! $this->countryAllowed($to->country, $allowedCountries)) {
            throw new SmsSendRefused(SmsRefusalReason::CountryNotAllowed);
        }

        $env = $this->environments()->current()?->environmentKey() ?? 'no-env';
        $day = gmdate('Y-m-d');

        // [key, max, decay seconds, reason]. A max of 0 disables that budget.
        $budgets = [
            [$env.':sms:cooldown:'.$to->cacheKey(), 1, $this->cooldownSeconds, SmsRefusalReason::Cooldown],
            [$env.':sms:number:'.$to->cacheKey(), $this->perNumberPerDay, self::DAY, SmsRefusalReason::NumberLimit],
            [$env.':sms:ip:'.($ip ?? 'unknown'), $this->perIpPerHour, 3600, SmsRefusalReason::IpLimit],
            [$env.':sms:environment:'.$day, $this->perEnvironmentPerDay, self::DAY, SmsRefusalReason::EnvironmentCap],
            ['sms:deployment:'.$day, $this->dailyCap, self::DAY, SmsRefusalReason::DailyCap],
        ];

        $live = array_values(array_filter($budgets, fn (array $budget): bool => $budget[1] > 0 && $budget[2] > 0));

        foreach ($live as [$key, $max, , $reason]) {
            if ($this->limiter->tooManyAttempts($key, $max)) {
                throw new SmsSendRefused($reason, $this->limiter->availableIn($key));
            }
        }

        foreach ($live as [$key, , $decay]) {
            $this->limiter->hit($key, $decay);
        }
    }

    /**
     * @param  list<string>|null  $narrower
     */
    private function countryAllowed(string $country, ?array $narrower): bool
    {
        if ($this->deploymentCountries !== [] && ! in_array($country, $this->deploymentCountries, true)) {
            return false;
        }

        return $narrower === null || in_array($country, $narrower, true);
    }
}
