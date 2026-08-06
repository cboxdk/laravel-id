<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Enums;

/**
 * An environment's mode. Sandbox is a behavioural flag on the same infrastructure
 * as production — relaxed rules, no real outbound email, clearly badged — not a
 * separate deployment.
 */
enum EnvironmentType: string
{
    case Production = 'production';
    case Sandbox = 'sandbox';

    public function label(): string
    {
        return match ($this) {
            self::Production => 'Production',
            self::Sandbox => 'Sandbox',
        };
    }

    public function isSandbox(): bool
    {
        return $this === self::Sandbox;
    }
}
