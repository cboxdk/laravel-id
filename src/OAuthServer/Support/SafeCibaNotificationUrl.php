<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\Kernel\Ssrf\UrlVerification;
use Cbox\Id\OAuthServer\Exceptions\UnsafeCibaNotificationEndpoint;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;

/**
 * SSRF gate for a CIBA ping, the same shared guard {@see SafeBackchannelLogoutUrl} uses:
 * private / reserved / cloud-metadata ranges refused, the connection pinned to the
 * addresses just checked, redirects never followed. The endpoint is operator-registered,
 * but a hostname that was public at registration can point anywhere by delivery time.
 */
class SafeCibaNotificationUrl
{
    /** @var list<string> */
    private const SCHEMES = ['https'];

    /**
     * @return array<string, mixed>
     *
     * @throws UnsafeCibaNotificationEndpoint
     */
    public static function pinnedOptions(string $url): array
    {
        if (! UrlVerification::enforced('cbox-id.oauth.ciba.ping.verify_url')) {
            return ['allow_redirects' => false];
        }

        try {
            return app(UrlGuard::class)->pinnedOptions($url, self::SCHEMES);
        } catch (BlockedUrl $e) {
            throw UnsafeCibaNotificationEndpoint::make($e->getMessage());
        }
    }
}
