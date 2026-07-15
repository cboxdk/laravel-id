<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions;

use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\Contracts\ActionRegistry;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Illuminate\Contracts\Foundation\Application;

/**
 * Resolves in-process {@see Action} handlers from `cbox-id.external_actions.hooks`.
 * Deny-by-default: a hook point with no configured classes runs nothing, and a
 * configured entry that is not a real {@see Action} is dropped, never trusted.
 */
final class ConfigActionRegistry implements ActionRegistry
{
    public function __construct(private readonly Application $app) {}

    public function for(HookPoint $hookPoint): array
    {
        $configured = config('cbox-id.external_actions.hooks.'.$hookPoint->value);

        if (! is_array($configured)) {
            return [];
        }

        $actions = [];

        foreach ($configured as $class) {
            if (! is_string($class) || ! is_a($class, Action::class, true)) {
                continue;
            }

            $resolved = $this->app->make($class);

            if ($resolved instanceof Action) {
                $actions[] = $resolved;
            }
        }

        return $actions;
    }
}
