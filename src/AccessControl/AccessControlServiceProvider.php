<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Console\SyncAppManifestsCommand;
use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\GrantGuard;
use Cbox\Id\AccessControl\Contracts\GroupRoleMappings;
use Cbox\Id\AccessControl\Contracts\ManifestFetcher;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Listeners\ReconcileGroupRolesOnDomainEvent;
use Cbox\Id\Kernel\Events\EventDelivered;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

class AccessControlServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        if (! $this->builtinDriver()) {
            // 'external' — bring-your-own RBAC. Fall back to deny-by-default so a
            // host that has not yet bound an adapter is refused, never trusted, and
            // never queries the built-in tables (which are not created in this mode).
            // A binding in the host's own provider wins over these.
            $this->app->singleton(AccessChecker::class, NullAccessChecker::class);
            $this->app->singleton(Roles::class, UnboundRoles::class);
            $this->app->singleton(GroupRoleMappings::class, UnboundGroupRoleMappings::class);

            return;
        }

        // Permissive by default and replaced by GovernanceServiceProvider, so a
        // deployment that loads governance gets the conflict gate without wiring it, and
        // one that does not is not surprised by refusals it configured no policy for.
        $this->app->singleton(GrantGuard::class, AllowAllGrants::class);
        $this->app->singleton(Roles::class, RoleService::class);
        $this->app->singleton(AccessChecker::class, HierarchyAwareAccessChecker::class);
        $this->app->singleton(AppManifests::class, ManifestSyncService::class);
        $this->app->singleton(ManifestFetcher::class, HttpManifestFetcher::class);
        $this->app->singleton(GroupRoleMappings::class, DatabaseGroupRoleMappings::class);
    }

    public function boot(): void
    {
        if (! $this->builtinDriver()) {
            // The built-in RBAC schema, the group→role reconciliation bridge, and the
            // manifest machinery all belong to the builtin driver only. In 'external'
            // mode the host owns authorization storage and reconciliation.
            return;
        }

        // Reconcile group→role assignments whenever a directory group's membership
        // changes (the SCIM→role bridge), via the domain-event outbox.
        Event::listen(EventDelivered::class, function (EventDelivered $delivered): void {
            $this->app->make(ReconcileGroupRolesOnDomainEvent::class)->handle($delivered);
        });

        // The module owns its own schema; the shared loader in IdServiceProvider is
        // non-recursive and does not reach this subdirectory, so it only runs under
        // the builtin driver.
        $this->loadMigrationsFrom(__DIR__.'/../../database/migrations/access-control');

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

    /**
     * Whether the built-in hierarchy-aware RBAC is active. False means the host
     * brings its own authorization backend (see docs/extension-points/custom-rbac.md).
     */
    private function builtinDriver(): bool
    {
        return config('cbox-id.access_control.driver', 'builtin') === 'builtin';
    }
}
