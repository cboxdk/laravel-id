<?php

declare(strict_types=1);

namespace Cbox\Id\Governance;

use Cbox\Id\Governance\Console\CloseOverdueCampaignsCommand;
use Cbox\Id\Governance\Contracts\AccessReviews;
use Cbox\Id\Governance\Contracts\SegregationOfDuties;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;

class GovernanceServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/cbox-id.php', 'cbox-id');

        $this->app->singleton(AccessReviews::class, DatabaseAccessReviews::class);
        $this->app->singleton(SegregationOfDuties::class, DatabaseSegregationOfDuties::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([CloseOverdueCampaignsCommand::class]);
        }

        // Auto-close overdue campaigns each minute (mirrors the provisioning drain
        // schedule). Gate with a config flag so hosts can drive it by hand instead.
        if (config('cbox-id.governance.schedule', true) === true) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
                $schedule->command(CloseOverdueCampaignsCommand::class)
                    ->everyMinute()
                    ->name('cbox-id:governance:close-overdue')
                    ->withoutOverlapping();
            });
        }
    }
}
