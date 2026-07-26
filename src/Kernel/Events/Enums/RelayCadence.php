<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events\Enums;

use Illuminate\Console\Scheduling\Event;

/**
 * How often the domain-event relay runs.
 *
 * A closed set rather than a free-form cron string: the relay is the single
 * chokepoint every subscriber hangs off, and a typo in a cron expression would
 * silently stop the entire fan-out. An unrecognised value falls back to the
 * safe default instead of leaving the schedule unset.
 */
enum RelayCadence: string
{
    case EveryMinute = 'every_minute';
    case EveryTwoMinutes = 'every_two_minutes';
    case EveryFiveMinutes = 'every_five_minutes';
    case EveryTenMinutes = 'every_ten_minutes';
    case EveryFifteenMinutes = 'every_fifteen_minutes';
    case EveryThirtyMinutes = 'every_thirty_minutes';
    case Hourly = 'hourly';

    public static function fromConfig(mixed $value): self
    {
        return (is_string($value) ? self::tryFrom($value) : null) ?? self::EveryMinute;
    }

    public function applyTo(Event $event): Event
    {
        return match ($this) {
            self::EveryMinute => $event->everyMinute(),
            self::EveryTwoMinutes => $event->everyTwoMinutes(),
            self::EveryFiveMinutes => $event->everyFiveMinutes(),
            self::EveryTenMinutes => $event->everyTenMinutes(),
            self::EveryFifteenMinutes => $event->everyFifteenMinutes(),
            self::EveryThirtyMinutes => $event->everyThirtyMinutes(),
            self::Hourly => $event->hourly(),
        };
    }
}
