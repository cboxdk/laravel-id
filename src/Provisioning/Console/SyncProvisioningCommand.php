<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Console;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\Id\Provisioning\Contracts\ProvisioningService;
use Cbox\Id\Provisioning\Enums\ConnectionStatus;
use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Illuminate\Console\Command;

/**
 * Full reconcile: for each targeted connection, enumerate its in-scope subjects,
 * enqueue an upsert for each, and drain immediately — so a newly-added connection
 * (or one that drifted) catches up its downstream app with the platform's current
 * users. `--connection=` limits it to one; otherwise every active connection in
 * every environment is reconciled.
 *
 * Like the drain, each connection is reconciled INSIDE its reconstructed
 * environment ({@see EnvironmentContext::withoutScope()} to learn the env, then
 * {@see EnvironmentContext::runAs()}), so enumeration and delivery only ever see
 * that environment's subjects and outbox rows.
 */
class SyncProvisioningCommand extends Command
{
    protected $signature = 'cbox-id:provisioning:sync {--connection= : Reconcile only this connection id}';

    protected $description = 'Reconcile downstream apps: enqueue and deliver an upsert for every in-scope subject.';

    public function handle(EnvironmentContext $context, ProvisioningService $provisioning): int
    {
        $only = $this->option('connection');
        $only = is_string($only) && $only !== '' ? $only : null;

        // Cross-environment enumeration is a system read — suspend the hard scope
        // to see connections in every environment, taking only id + env id.
        $connections = $context->withoutScope(function () use ($only): array {
            $query = ProvisioningConnection::query()->where('status', ConnectionStatus::Active->value);

            if ($only !== null) {
                $query->whereKey($only);
            }

            return $query->get(['id', 'environment_id'])
                ->map(fn (ProvisioningConnection $connection): array => [
                    'id' => $connection->id,
                    'environment_id' => $connection->environment_id,
                ])
                ->all();
        });

        $total = 0;

        foreach ($connections as $connection) {
            $enqueued = $context->runAs(
                GenericEnvironment::of($connection['environment_id']),
                function () use ($provisioning, $connection): int {
                    $enqueued = $provisioning->reconcileConnection($connection['id']);
                    $provisioning->drainConnection($connection['id']);

                    return $enqueued;
                },
            );

            $total += $enqueued;
        }

        $this->info(sprintf('Reconciled %d connection(s), enqueued %d operation(s).', count($connections), $total));

        return self::SUCCESS;
    }
}
