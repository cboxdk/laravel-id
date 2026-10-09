<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\SmsFactorPolicy;

/**
 * The current environment's {@see SmsFactorPolicy}. One per environment; an environment
 * that never stored one gets the default — SMS off.
 *
 * Environment-level only, by design: whether the deployment texts a country is a cost and
 * fraud decision for whoever pays the SMS bill, not something an organization inside the
 * environment should be able to widen.
 */
interface SmsFactorPolicies
{
    public function forEnvironment(): SmsFactorPolicy;

    public function setForEnvironment(SmsFactorPolicy $policy): void;
}
