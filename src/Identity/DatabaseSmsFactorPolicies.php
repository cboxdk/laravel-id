<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\SmsFactorPolicies;
use Cbox\Id\Identity\Models\SmsFactorPolicyRecord;
use Cbox\Id\Identity\ValueObjects\SmsFactorPolicy;

/**
 * The default {@see SmsFactorPolicies}: one row per environment in `sms_factor_policies`,
 * scoped by the environment the request runs in. No row is the default policy — off.
 *
 * Not memoised: it is read on the sign-in and enrolment paths only, once or twice a
 * request, and a memo in a singleton is exactly how a tightened policy goes on being
 * served stale by a warm worker (see `DatabaseAuthPolicies`).
 */
class DatabaseSmsFactorPolicies implements SmsFactorPolicies
{
    public function forEnvironment(): SmsFactorPolicy
    {
        return SmsFactorPolicyRecord::query()->first()?->toPolicy() ?? new SmsFactorPolicy;
    }

    public function setForEnvironment(SmsFactorPolicy $policy): void
    {
        $record = SmsFactorPolicyRecord::query()->first() ?? new SmsFactorPolicyRecord;

        $record->forceFill([
            'enabled' => $policy->enabled,
            'allowed_countries' => $policy->allowedCountries,
            'privileged_need_stronger_factor' => $policy->privilegedNeedStrongerFactor,
        ])->save();
    }
}
