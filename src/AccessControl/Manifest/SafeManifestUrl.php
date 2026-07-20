<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Manifest;

use Cbox\Id\AccessControl\Exceptions\UnsafeManifestUrl;
use Cbox\Id\Federation\Support\SafeFederationUrl;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;

/**
 * SSRF gate for pulling an app's well-known manifest. The URL is app-controlled and
 * fetched server-side, so it goes through the shared `cboxdk/laravel-ssrf` guard —
 * scheme/credential checks, dual-stack resolution, private/reserved/cloud-metadata
 * blocking, and DNS pinning — exactly like {@see SafeFederationUrl}.
 */
class SafeManifestUrl
{
    /**
     * Validate the URL and return Guzzle options pinning the connection to the exact
     * IPs just validated, so a DNS rebind between check and connect can't redirect
     * the request to an internal address. Empty array when enforcement is disabled
     * (single-tenant/on-prem reaching an internal app).
     *
     * @return array<string, mixed>
     *
     * @throws UnsafeManifestUrl
     */
    public static function pinnedOptions(string $url): array
    {
        if (config('cbox-id.access_control.verify_manifest_url', true) !== true) {
            return [];
        }

        try {
            return app(UrlGuard::class)->pinnedOptions($url);
        } catch (BlockedUrl $e) {
            throw UnsafeManifestUrl::make($e->getMessage());
        }
    }
}
