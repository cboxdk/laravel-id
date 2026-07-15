<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Contracts;

use Cbox\Id\ExternalActions\Enums\HookPoint;

/**
 * Resolves the in-process {@see Action} handlers registered for a hook point.
 * Deny-by-default: a hook point with no configured handlers yields an empty list
 * (nothing runs), and a configured class that does not implement {@see Action} is
 * dropped, never trusted.
 */
interface ActionRegistry
{
    /**
     * @return list<Action>
     */
    public function for(HookPoint $hookPoint): array;
}
