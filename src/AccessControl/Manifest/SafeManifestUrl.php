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
            // REDIRECTS STAY REFUSED even when host verification is switched off.
            //
            // The toggle exists so an on-prem deployment can reach an internal host it
            // genuinely owns. It was never meant to say "and follow this anywhere it points":
            // returning a bare `[]` handed the caller Guzzle's default, which chases up to
            // five hops. An operator who set the flag to allow one internal issuer also
            // re-enabled redirect chasing for every outbound fetch on the plane — so a URL
            // the tenant controls could 302 to `169.254.169.254` and the metadata service
            // answered.
            //
            // `laravel-ssrf`'s own `Guard::pinnedOptions()` refuses redirects unconditionally
            // for exactly this reason, and `laravel-siem`'s adapter already mirrors it. These
            // four did not.
            return ['allow_redirects' => false];
        }

        try {
            return app(UrlGuard::class)->pinnedOptions($url);
        } catch (BlockedUrl $e) {
            throw UnsafeManifestUrl::make($e->getMessage());
        }
    }
}
