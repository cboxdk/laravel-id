<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\Kernel\Ssrf\UrlVerification;
use Cbox\Id\OAuthServer\Exceptions\UnsafeBackchannelLogoutUri;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;

/**
 * SSRF gate for delivering a logout token. The URI is registered by the client — through
 * the console, or by anyone at all through open Dynamic Client Registration — and called
 * server-side, so it goes through the shared `cboxdk/laravel-ssrf` guard exactly like a
 * webhook: scheme and credential checks, dual-stack resolution, private / reserved /
 * cloud-metadata ranges refused, and the connection pinned to the addresses just checked
 * so a DNS rebind between check and connect lands nowhere.
 */
class SafeBackchannelLogoutUrl
{
    /**
     * HTTPS only at the sink. A logout token names a person and a session; the guard's
     * configured scheme list is wider because it serves several sinks.
     *
     * @var list<string>
     */
    private const SCHEMES = ['https'];

    /**
     * Guzzle options pinning the connection to the validated addresses.
     *
     * @return array<string, mixed>
     *
     * @throws UnsafeBackchannelLogoutUri
     */
    public static function pinnedOptions(string $url): array
    {
        if (! UrlVerification::enforced('cbox-id.oauth.backchannel_logout.verify_url')) {
            // REDIRECTS STAY REFUSED even with host verification off — the toggle is for
            // reaching an internal host an on-prem operator owns, not for following a
            // relying party's 302 to wherever it points. Same rule as every other
            // outbound plane; see SafeWebhookUrl.
            return ['allow_redirects' => false];
        }

        try {
            return app(UrlGuard::class)->pinnedOptions($url, self::SCHEMES);
        } catch (BlockedUrl $e) {
            throw UnsafeBackchannelLogoutUri::make($e->getMessage());
        }
    }
}
