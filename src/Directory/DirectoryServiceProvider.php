<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Console\DirectorySyncCommand;
use Cbox\Id\Directory\Connectors\GoogleWorkspaceConnector;
use Cbox\Id\Directory\Connectors\MicrosoftEntraConnector;
use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Contracts\DirectoryUsers;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;

class DirectoryServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Directories::class, DirectoryService::class);
        $this->app->singleton(DirectorySync::class, DatabaseDirectorySync::class);
        $this->app->singleton(DirectoryUsers::class, DatabaseDirectoryUsers::class);
        $this->app->singleton(DirectoryGroups::class, DatabaseDirectoryGroups::class);

        // API-pull directory connectors (Google Workspace, Microsoft Entra). A host
        // can register more by rebinding this with additional connectors.
        $this->app->singleton(DirectoryConnectors::class, fn (): DirectoryConnectors => new DirectoryConnectors([
            new GoogleWorkspaceConnector,
            new MicrosoftEntraConnector,
        ]));
    }

    public function boot(): void
    {
        // RECONCILE ON A TIMER, because a pull connector has no other trigger.
        //
        // The only caller of `cbox-id:directory:sync` was the console screen that CREATES a
        // directory, so a customer connected Entra, saw one successful sync, and never got
        // another. Joiners never arrived; leavers were never deprovisioned — while
        // `docs/guides/sync-users-in.md` tells them syncing is what "closes the gap where a
        // leaver still has a working account". Every comparable job in this package is
        // scheduled by its own provider; this one was not.
        //
        // Hourly, not every minute: it is a full pull of a customer's directory over
        // somebody else's rate-limited API, and what it races is a notice period.
        if (config('cbox-id.directory.schedule', true) === true) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
                $schedule->command(DirectorySyncCommand::class)
                    ->hourly()
                    ->name('cbox-id:directory:sync')
                    ->withoutOverlapping();
            });
        }
    }
}
