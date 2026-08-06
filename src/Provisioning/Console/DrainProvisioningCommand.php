<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Console;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Provisioning\Enums\ConnectionStatus;
use Cbox\Id\Provisioning\Jobs\DrainProvisioningConnection;
use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Illuminate\Console\Command;

/**
 * Fan a drain job out to every active connection in EVERY environment.
 *
 * This is the ONE genuinely environment-spanning system step, and it is careful
 * to be only a dispatcher: under {@see EnvironmentContext::withoutScope()} it
 * enumerates all active connections across the whole deployment and dispatches
 * one {@see DrainProvisioningConnection} per connection. It never delivers and
 * never reads an outbox row across the boundary — each dispatched job re-enters
 * its own connection's environment first. Scheduled every minute by the service
 * provider (mirroring the Webhooks retry schedule), or run by hand.
 */
class DrainProvisioningCommand extends Command
{
    protected $signature = 'cbox-id:provisioning:drain';

    protected $description = 'Dispatch an outbox drain for every active provisioning connection across all environments.';

    public function handle(EnvironmentContext $context): int
    {
        $connectionIds = $context->withoutScope(
            fn (): array => ProvisioningConnection::query()
                ->where('status', ConnectionStatus::Active->value)
                ->pluck('id')
                ->all(),
        );

        foreach ($connectionIds as $connectionId) {
            if (is_string($connectionId)) {
                DrainProvisioningConnection::dispatch($connectionId);
            }
        }

        $this->info(sprintf('Dispatched %d provisioning drain job(s).', count($connectionIds)));

        return self::SUCCESS;
    }
}
