<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Console;

use Cbox\Id\AccessControl\Jobs\SyncAppManifestJob;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\OAuthServer\Models\Client;
use Illuminate\Console\Command;

/**
 * Re-pull the manifest of every app that publishes a `manifest_url`, across all
 * environments. A dispatcher only: it enumerates apps under a suspended tenancy
 * scope and fans one {@see SyncAppManifestJob} out per app — each job re-enters its
 * own environment before fetching or writing. Scheduled hourly by the provider, or
 * run by hand (optionally for a single app with `--client`).
 */
class SyncAppManifestsCommand extends Command
{
    protected $signature = 'cbox-id:app-manifests:sync {--client= : Only sync the app with this client_id}';

    protected $description = 'Pull + sync app authorization manifests from their published URLs across all environments.';

    public function handle(EnvironmentContext $context): int
    {
        $client = $this->option('client');
        $only = is_string($client) ? $client : null;

        $clientIds = $context->withoutScope(
            fn (): array => Client::query()
                ->whereNotNull('manifest_url')
                ->when($only !== null, fn ($query) => $query->where('client_id', $only))
                ->pluck('client_id')
                ->all(),
        );

        $count = 0;
        foreach ($clientIds as $clientId) {
            if (is_string($clientId)) {
                SyncAppManifestJob::dispatch($clientId);
                $count++;
            }
        }

        $this->info(sprintf('Dispatched %d app-manifest sync job(s).', $count));

        return self::SUCCESS;
    }
}
