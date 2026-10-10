<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\Enums;

/**
 * Why a flag evaluated the way it did — the rule that decided, in precedence order:
 *
 *  1. `disabled` — the flag is switched off: off for everyone, whatever else it says;
 *  2. `user_target` — a rule names this user;
 *  3. `organization_target` — a rule names the organization the question is asked in;
 *  4. `rollout` — the subject's stable bucket falls inside the rollout percentage;
 *  5. `default` — nothing above matched, so the flag's default value applies.
 *
 * `unknown_flag` answers for a key the environment does not define: always off, so code
 * that ships ahead of its flag fails closed.
 */
enum EvaluationReason: string
{
    case Disabled = 'disabled';
    case UserTarget = 'user_target';
    case OrganizationTarget = 'organization_target';
    case Rollout = 'rollout';
    case Default = 'default';
    case UnknownFlag = 'unknown_flag';
}
