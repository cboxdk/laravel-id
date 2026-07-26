<?php

declare(strict_types=1);

namespace Cbox\Id\Maintenance;

use Cbox\Id\Maintenance\Console\PruneCommand;
use Cbox\Id\Support\PackageConfigMerger;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;

class MaintenanceServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        PackageConfigMerger::mergeInto($this->app, __DIR__.'/../../config/cbox-id.php', 'cbox-id');

        $this->app->singleton(Pruner::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([PruneCommand::class]);
        }

        // Daily rather than per-minute: the sweep is bulk deletion, and running it
        // off-peak once a day keeps it away from the traffic it is cleaning up after.
        // Gate with a config flag so hosts can drive it from their own scheduler.
        if (config('cbox-id.prune.schedule', true) === true) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
                $schedule->command(PruneCommand::class)
                    ->dailyAt($this->scheduleTime())
                    ->name('cbox-id:prune')
                    ->withoutOverlapping();
            });
        }
    }

    private function scheduleTime(): string
    {
        $time = config('cbox-id.prune.time', '03:10');

        return is_string($time) && preg_match('/^\d{1,2}:\d{2}$/', $time) === 1 ? $time : '03:10';
    }
}
