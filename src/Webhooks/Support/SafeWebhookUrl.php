<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Support;

use Cbox\Id\Kernel\Ssrf\UrlVerification;
use Cbox\Id\Webhooks\Exceptions\UnsafeWebhookUrl;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;

/**
 * SSRF gate for outbound webhook URLs. The actual guarding — scheme/credential
 * checks, dual-stack resolution, private/reserved/cloud-metadata blocking, and
 * DNS pinning — lives in the shared, independently-tested `cboxdk/laravel-ssrf`
 * package. This adapter keeps the platform's own on/off toggle and domain
 * exception, so callers and their tests are unaffected.
 */
class SafeWebhookUrl
{
    /**
     * Webhook deliveries are HTTPS-ONLY. A payload carries the full event body —
     * emails, names, org ids — and the HMAC signature authenticates it but does not
     * encrypt it, so a plaintext `http://` endpoint puts every subscriber's PII on the
     * wire in the clear. The SSRF guard's configured scheme list is deliberately wider
     * (it serves several sinks), so narrow it here at the sink that needs it.
     *
     * @var list<string>
     */
    private const SCHEMES = ['https'];

    public static function isSafe(string $url): bool
    {
        try {
            self::assert($url);

            return true;
        } catch (UnsafeWebhookUrl) {
            return false;
        }
    }

    public static function assert(string $url): void
    {
        // A single-tenant/on-prem deployment can disable enforcement to deliver
        // to internal hosts (also disabled in the delivery tests). Keep it true in
        // any multi-tenant deployment.
        if (! UrlVerification::enforced('cbox-id.webhooks.verify_url')) {
            return;
        }

        try {
            app(UrlGuard::class)->assertSafe($url, self::SCHEMES);
        } catch (BlockedUrl $e) {
            throw UnsafeWebhookUrl::make($e->getMessage());
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
     * @throws UnsafeWebhookUrl
     */
    public static function pinnedOptions(string $url): array
    {
        if (! UrlVerification::enforced('cbox-id.webhooks.verify_url')) {
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
            return app(UrlGuard::class)->pinnedOptions($url, self::SCHEMES);
        } catch (BlockedUrl $e) {
            throw UnsafeWebhookUrl::make($e->getMessage());
        }
    }
}
