<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events;

use Cbox\Id\Kernel\Events\Console\EventBacklogCommand;
use Cbox\Id\Kernel\Events\Console\RelayEventsCommand;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\Contracts\RelayBacklog;
use Cbox\Id\Kernel\Events\Enums\RelayCadence;
use Cbox\Id\Kernel\Events\Support\DatabaseRelayBacklog;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;

class EventsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(EventBus::class, DatabaseEventBus::class);
        $this->app->singleton(RelayBacklog::class, DatabaseRelayBacklog::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([RelayEventsCommand::class, EventBacklogCommand::class]);
        }

        // Drive the outbox on a schedule. Emitting only writes a row — nothing is
        // delivered until the relay runs — so without this EVERY subscriber is inert:
        // no webhook fires, no usage is metered, outbound provisioning never runs, and
        // a host listening for role changes never hears one. The app looks healthy
        // throughout, which is exactly why the omission survived so long. Every other
        // module registered its own schedule; the Events kernel was the one that didn't.
        //
        // Both the batch size and the cadence are configurable: tuning the relay used
        // to mean turning the whole schedule OFF and re-registering it in the host.
        //
        // Opt out to drive flushPending() yourself (a queue worker, a different cadence).
        if (config('cbox-id.events.schedule_relay', true) === true) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
                $event = $schedule->command(RelayEventsCommand::class, ['--limit' => (string) $this->relayLimit()])
                    ->name('cbox-id:events:relay')
                    ->withoutOverlapping()
                    // Report the depth AFTER every pass. Relay lag was otherwise
                    // completely silent — a stalled relay looked exactly like an idle
                    // one until a customer noticed the missing webhooks.
                    ->after(fn () => $this->reportBacklog());

                RelayCadence::fromConfig(config('cbox-id.events.relay_cadence'))->applyTo($event);
            });
        }
    }

    private function relayLimit(): int
    {
        $configured = config('cbox-id.events.relay_limit', 100);

        return max(1, is_numeric($configured) ? (int) $configured : 100);
    }

    /**
     * Log the outbox depth once a pass, and escalate to a warning once the waiting
     * depth crosses the threshold. Deliberately a LOG line and a resolvable
     * {@see RelayBacklog} contract, not a metrics call: this package must not force
     * a telemetry runtime on its host.
     */
    private function reportBacklog(): void
    {
        $threshold = $this->backlogWarningThreshold();
        $depth = $this->app->make(RelayBacklog::class)->depth();
        $context = $depth->toArray() + ['warning_threshold' => $threshold];

        if ($depth->waiting >= $threshold) {
            Log::warning('cbox-id: domain-event relay backlog is above the warning threshold.', $context);

            return;
        }

        Log::debug('cbox-id: domain-event relay backlog.', $context);
    }

    private function backlogWarningThreshold(): int
    {
        $configured = config('cbox-id.events.backlog_warning_threshold', 1000);

        return max(1, is_numeric($configured) ? (int) $configured : 1000);
    }
}
