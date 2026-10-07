<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning;

use Cbox\Id\Directory\DirectoryServiceProvider;
use Cbox\Id\Identity\Contracts\ErasureSteps;
use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;
use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Provisioning\Console\DrainProvisioningCommand;
use Cbox\Id\Provisioning\Console\SyncProvisioningCommand;
use Cbox\Id\Provisioning\Contracts\ProvisioningConnections;
use Cbox\Id\Provisioning\Contracts\ProvisioningService;
use Cbox\Id\Provisioning\Contracts\ScimClient;
use Cbox\Id\Provisioning\Erasure\ProvisioningErasureStep;
use Cbox\Id\Provisioning\Listeners\ProvisionOnDomainEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

/**
 * Wires OUTBOUND SCIM 2.0 provisioning: the SCIM client, the connection registry
 * and the outbox translator/drain, plus the thin listener that enqueues on every
 * delivered domain event and the scheduled per-connection drain.
 *
 * The mirror of {@see DirectoryServiceProvider} (inbound SCIM
 * server) — here the platform is the SCIM CLIENT pushing changes OUT.
 */
class ProvisioningServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // This module's share of a GDPR erasure (see SubjectEraser): the personal data it
        // owns is erased by the module that owns it.
        $this->callAfterResolving(ErasureSteps::class, static function (ErasureSteps $steps, Application $app): void {
            $steps->register($app->make(ProvisioningErasureStep::class));
        });

        // The downstream SCIM bearer/client secret (ProvisioningConnection::secretContext()).
        // Registered so a master-key rotation (`cbox-id:crypto:rewrap`) re-seals it.
        $this->callAfterResolving(SealedColumns::class, static function (SealedColumns $columns): void {
            $columns->register(new SealedColumn('provisioning_connections', 'auth_secret_encrypted', 'cbox-id:provisioning-connection:'));
        });

        $this->app->singleton(ScimClient::class, HttpScimClient::class);
        $this->app->singleton(ProvisioningConnections::class, DatabaseProvisioningConnections::class);
        $this->app->singleton(ProvisioningService::class, OutboxProvisioningService::class);
    }

    public function boot(): void
    {
        // Enqueue outbound operations for every delivered domain event. The
        // listener only writes outbox rows (in the delivering environment); it
        // never makes a SCIM call on the request thread.
        Event::listen(EventDelivered::class, function (EventDelivered $delivered): void {
            $this->app->make(ProvisionOnDomainEvent::class)->handle($delivered);
        });

        if ($this->app->runningInConsole()) {
            $this->commands([SyncProvisioningCommand::class, DrainProvisioningCommand::class]);
        }

        // Drain due operations on a schedule, so a transient downstream outage
        // recovers without a caller wiring the loop by hand. Opt out to drive
        // cbox-id:provisioning:drain yourself. Mirrors the Webhooks retry schedule.
        if (config('cbox-id.provisioning.schedule', true) === true) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
                $schedule->command(DrainProvisioningCommand::class)
                    ->everyMinute()
                    ->name('cbox-id:provisioning:drain')
                    ->withoutOverlapping();
            });
        }
    }
}
