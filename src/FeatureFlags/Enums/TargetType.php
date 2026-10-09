<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\Enums;

/**
 * What a targeting rule names: one user (a subject) or one organization. A user rule
 * outranks an organization rule — see {@see EvaluationReason} for the full order.
 */
enum TargetType: string
{
    case User = 'user';
    case Organization = 'organization';
}
