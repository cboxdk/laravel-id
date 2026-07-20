<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\ManifestFetcher;
use Cbox\Id\AccessControl\Exceptions\ManifestFetchFailed;
use Cbox\Id\AccessControl\Manifest\Manifest;
use Cbox\Id\AccessControl\Manifest\ManifestParser;
use Cbox\Id\AccessControl\Manifest\SafeManifestUrl;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

/**
 * Fetches an app's manifest from its well-known URL over HTTP, through the SSRF
 * guard (pinned resolution, no redirects), and parses it. Server-side, app-
 * controlled URL — hence the guard.
 */
class HttpManifestFetcher implements ManifestFetcher
{
    public function __construct(private readonly ManifestParser $parser) {}

    public function fetch(string $url): Manifest
    {
        // Throws UnsafeManifestUrl on a blocked host; returns options that pin the
        // connection to the validated IPs.
        $pinned = SafeManifestUrl::pinnedOptions($url);

        $timeout = config('cbox-id.access_control.fetch_timeout', 10);

        try {
            $response = Http::withOptions($pinned)
                ->timeout(is_int($timeout) ? $timeout : 10)
                ->acceptJson()
                ->get($url);
        } catch (ConnectionException $e) {
            throw ManifestFetchFailed::make($e->getMessage());
        }

        if (! $response->successful()) {
            throw ManifestFetchFailed::make("endpoint returned HTTP {$response->status()}.");
        }

        $body = $response->json();

        if (! is_array($body)) {
            throw ManifestFetchFailed::make('response body was not a JSON object.');
        }

        /** @var array<string, mixed> $body */
        return $this->parser->parse($body);
    }
}
