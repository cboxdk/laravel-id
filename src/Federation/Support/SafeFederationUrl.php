<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Support;

use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Kernel\Ssrf\UrlVerification;
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
class SafeFederationUrl
{
    public static function assert(string $url): void
    {
        // A single-tenant/on-prem deployment can disable enforcement to reach an
        // internal IdP (also disabled in the flow tests). Keep it true in any
        // multi-tenant deployment.
        if (! UrlVerification::enforced('cbox-id.federation.verify_url')) {
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
     * and the connect can't redirect the request to an internal address. When
     * enforcement is disabled it still refuses redirects — see the body.
     *
     * @return array<string, mixed>
     *
     * @throws UnsafeFederationUrl
     */
    public static function pinnedOptions(string $url): array
    {
        if (! UrlVerification::enforced('cbox-id.federation.verify_url')) {
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
            throw UnsafeFederationUrl::make($e->getMessage());
        }
    }
}
