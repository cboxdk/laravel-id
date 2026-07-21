<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events;

use Cbox\Id\Kernel\Events\Console\RelayEventsCommand;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;

class EventsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(EventBus::class, DatabaseEventBus::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([RelayEventsCommand::class]);
        }

        // Drive the outbox on a schedule. Emitting only writes a row — nothing is
        // delivered until the relay runs — so without this EVERY subscriber is inert:
        // no webhook fires, no usage is metered, outbound provisioning never runs, and
        // a host listening for role changes never hears one. The app looks healthy
        // throughout, which is exactly why the omission survived so long. Every other
        // module registered its own schedule; the Events kernel was the one that didn't.
        //
        // Opt out to drive flushPending() yourself (a queue worker, a different cadence).
        if (config('cbox-id.events.schedule_relay', true) === true) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
                $schedule->command(RelayEventsCommand::class)
                    ->everyMinute()
                    ->name('cbox-id:events:relay')
                    ->withoutOverlapping();
            });
        }
    }
}
