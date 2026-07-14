<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Support;

use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Webhooks\Support\SafeWebhookUrl;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;

/**
 * SSRF gate for outbound IdP endpoints an org admin configures (e.g. an OIDC
 * `token_endpoint`). Reuses the shared, independently-tested `cboxdk/laravel-ssrf`
 * package — scheme/credential checks, dual-stack resolution, private/reserved/
 * cloud-metadata blocking, and DNS pinning — exactly like {@see SafeWebhookUrl},
 * keeping the platform's own on/off toggle so callers and their tests are unaffected.
 */
final class SafeFederationUrl
{
    public static function assert(string $url): void
    {
        // A single-tenant/on-prem deployment can disable enforcement to reach an
        // internal IdP (also disabled in the flow tests). Keep it true in any
        // multi-tenant deployment.
        if (config('cbox-id.federation.verify_url', true) !== true) {
            return;
        }

        try {
            app(UrlGuard::class)->assertSafe($url);
        } catch (BlockedUrl $e) {
            throw UnsafeFederationUrl::make($e->getMessage());
        }
    }

    /**
     * Validate the URL and return Guzzle options that PIN the connection to the
     * exact IPs just validated — one DNS resolution, so a rebind between the check
     * and the connect can't redirect the request to an internal address. Returns
     * an empty array when enforcement is disabled.
     *
     * @return array<string, mixed>
     *
     * @throws UnsafeFederationUrl
     */
    public static function pinnedOptions(string $url): array
    {
        if (config('cbox-id.federation.verify_url', true) !== true) {
            return [];
        }

        try {
            return app(UrlGuard::class)->pinnedOptions($url);
        } catch (BlockedUrl $e) {
            throw UnsafeFederationUrl::make($e->getMessage());
        }
    }
}
