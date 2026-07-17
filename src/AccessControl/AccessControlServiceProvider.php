<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Console\SyncAppManifestsCommand;
use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\ManifestFetcher;
use Cbox\Id\AccessControl\Contracts\Roles;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;

final class AccessControlServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Roles::class, RoleService::class);
        $this->app->singleton(AccessChecker::class, HierarchyAwareAccessChecker::class);
        $this->app->singleton(AppManifests::class, ManifestSyncService::class);
        $this->app->singleton(ManifestFetcher::class, HttpManifestFetcher::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([SyncAppManifestsCommand::class]);
        }

        // Re-pull every app's published manifest hourly, so a role/permission an app
        // adds shows up without a manual "Sync now". SDK/push paths keep it current
        // in real time; this is the safety net for the pull transport.
        if (config('cbox-id.access_control.schedule', true) === true) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
                $schedule->command(SyncAppManifestsCommand::class)
                    ->hourly()
                    ->name('cbox-id:access-control:sync-manifests')
                    ->withoutOverlapping();
            });
        }
    }
}
