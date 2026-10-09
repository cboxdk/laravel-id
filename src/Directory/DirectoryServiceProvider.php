<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Console\DirectorySyncCommand;
use Cbox\Id\Directory\Connectors\BambooHrConnector;
use Cbox\Id\Directory\Connectors\GoogleWorkspaceConnector;
use Cbox\Id\Directory\Connectors\HiBobConnector;
use Cbox\Id\Directory\Connectors\MicrosoftEntraConnector;
use Cbox\Id\Directory\Connectors\PersonioConnector;
use Cbox\Id\Directory\Connectors\RipplingConnector;
use Cbox\Id\Directory\Connectors\WorkdayConnector;
use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Contracts\DirectoryUsers;
use Cbox\Id\Directory\Contracts\PullDirectories;
use Cbox\Id\Directory\Erasure\DirectoryUsersErasureStep;
use Cbox\Id\Identity\Contracts\ErasureSteps;
use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class DirectoryServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // This module's share of a GDPR erasure (see SubjectEraser): the personal data it
        // owns is erased by the module that owns it.
        $this->callAfterResolving(ErasureSteps::class, static function (ErasureSteps $steps, Application $app): void {
            $steps->register($app->make(DirectoryUsersErasureStep::class));
        });

        // A pull directory's provider credentials, bound to the directory id.
        // Registered so a master-key rotation (`cbox-id:crypto:rewrap`) re-seals it.
        $this->callAfterResolving(SealedColumns::class, static function (SealedColumns $columns): void {
            $columns->register(new SealedColumn('directories', 'credentials', 'cbox-id:directory-credentials:'));
        });

        $this->app->singleton(Directories::class, DirectoryService::class);
        $this->app->singleton(PullDirectories::class, DirectoryService::class);
        $this->app->singleton(DirectorySync::class, DatabaseDirectorySync::class);
        $this->app->singleton(DirectoryUsers::class, DatabaseDirectoryUsers::class);
        $this->app->singleton(DirectoryGroups::class, DatabaseDirectoryGroups::class);

        // API-pull directory connectors: the identity directories (Google Workspace,
        // Microsoft Entra) and the HR systems (Workday, BambooHR, Rippling, HiBob,
        // Personio). A host can register more by rebinding this with additional connectors.
        $this->app->singleton(DirectoryConnectors::class, fn (): DirectoryConnectors => new DirectoryConnectors([
            new GoogleWorkspaceConnector,
            new MicrosoftEntraConnector,
            new WorkdayConnector,
            new BambooHrConnector,
            new RipplingConnector,
            new HiBobConnector,
            new PersonioConnector,
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
        // Every directory has its OWN pace (`sync_interval_minutes`, hourly by default, never
        // more often than every fifteen minutes): the scheduler ticks every fifteen minutes
        // and pulls only the directories that are due. A directory with no interval of its
        // own is pulled hourly, as every directory was before the interval existed. Not every
        // minute: it is a pull of a customer's directory over somebody else's rate-limited
        // API, and what it races is a notice period.
        if (config('cbox-id.directory.schedule', true) === true) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
                $schedule->command(DirectorySyncCommand::class, ['--due'])
                    ->everyFifteenMinutes()
                    ->name('cbox-id:directory:sync')
                    ->withoutOverlapping();
            });
        }
    }
}
