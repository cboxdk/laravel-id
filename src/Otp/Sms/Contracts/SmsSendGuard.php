<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Contracts;

use Cbox\Id\Otp\Sms\Exceptions\SmsSendRefused;
use Cbox\Id\Otp\Sms\RateLimitedSmsSendGuard;
use Cbox\Id\Otp\Sms\ValueObjects\PhoneNumber;

/**
 * The toll-fraud and anti-abuse gate in front of every text: decides, BEFORE a provider
 * is called, whether this number may be texted now.
 *
 * SMS pumping works because sending is free to the requester and costs the sender: an
 * attacker drives a public "text me a code" form at premium-rate ranges they share
 * revenue on. The default {@see RateLimitedSmsSendGuard} answers with a country
 * allow-list, a per-number cooldown, per-number and per-IP caps, a per-environment daily
 * cap and a deployment-wide daily circuit breaker. A host that pays for a fraud-scoring
 * service binds its own guard here (and can delegate to the default for the caps).
 */
interface SmsSendGuard
{
    /**
     * Admit one send, counting it against every budget — or refuse it and count nothing.
     *
     * @param  list<string>|null  $allowedCountries  a narrower allow-list from the caller (an environment's policy); null for none
     *
     * @throws SmsSendRefused
     */
    public function admit(PhoneNumber $to, ?string $ip = null, ?array $allowedCountries = null): void;
}
