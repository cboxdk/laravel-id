<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Jobs;

use Cbox\Id\AccessControl\AppManifestPuller;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\Id\OAuthServer\Models\Client;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Throwable;

/**
 * Pulls + syncs one app's manifest. Dispatched (one per app) by the scheduled
 * command, which enumerates apps across all environments; this job re-enters the
 * app's OWN environment before it fetches or writes, so the hard tenancy boundary
 * is never crossed. A failure for one app is reported and swallowed — it never
 * blocks another app's sync.
 */
final class SyncAppManifestJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public function __construct(private readonly string $clientId) {}

    public function handle(EnvironmentContext $context, AppManifestPuller $puller): void
    {
        // Resolve the app across the boundary to learn its environment, then enter it.
        $client = $context->withoutScope(
            fn (): ?Client => Client::query()->where('client_id', $this->clientId)->first(),
        );

        if ($client === null) {
            return;
        }

        $context->set(GenericEnvironment::of($client->environment_id));

        try {
            $puller->pull($client);
        } catch (Throwable $e) {
            // A bad or unreachable app must not fail the fleet-wide sweep; its
            // existing declared catalog simply stands until the next successful pull.
            report($e);
        }
    }
}
