<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\ManifestFetcher;
use Cbox\Id\AccessControl\Jobs\SyncAppManifestJob;
use Cbox\Id\AccessControl\Manifest\ManifestSyncResult;
use Cbox\Id\OAuthServer\Models\Client;

/**
 * The "pull" transport, composed: fetch an app's manifest from its published URL,
 * then sync it. Used by the scheduled {@see SyncAppManifestJob}
 * and by an on-demand "Sync now" in the console. Runs inside the caller's
 * environment; sync writes to that environment's catalog.
 */
class AppManifestPuller
{
    public function __construct(
        private readonly ManifestFetcher $fetcher,
        private readonly AppManifests $manifests,
    ) {}

    /**
     * Fetch + sync the app's declared catalog from its `manifest_url`. Returns null
     * if the app publishes no URL (it pushes instead). Fetch/parse/SSRF errors
     * propagate — the caller decides whether to swallow them (the scheduled job
     * does, per-app, so one bad app never breaks the run).
     */
    public function pull(Client $client): ?ManifestSyncResult
    {
        $url = $client->manifest_url;

        if (! is_string($url) || $url === '') {
            return null;
        }

        return $this->manifests->sync($client->client_id, $this->fetcher->fetch($url));
    }
}
