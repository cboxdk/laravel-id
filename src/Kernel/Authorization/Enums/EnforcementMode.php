<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Enums;

/**
 * How an entitlement is enforced (chosen per key).
 */
enum EnforcementMode: string
{
    /** Embedded in tokens at mint; revocation bounded by token TTL. Coarse, slow-changing. */
    case Claims = 'claims';

    /** Checked live via the decision API / edge cache; revocable immediately. */
    case DecisionApi = 'decision_api';
}
