<?php

declare(strict_types=1);

namespace Cbox\Id\Migration\Support;

use Cbox\Id\Kernel\Ssrf\UrlVerification;
use Cbox\Id\Webhooks\Support\SafeWebhookUrl;
use Cbox\Ssrf\Contracts\UrlGuard;

/**
 * SSRF gate for the customer endpoint an old login is delegated to.
 *
 * THE FIFTH PLANE, and the one that matters most. Webhooks, SCIM, federation and manifests
 * each have one of these; this request is the only outbound call in the package whose body
 * is a live plaintext password, and it was the one still deciding the toggle inline. That
 * is how it ended up as the single plane where relaxing host verification also switched
 * redirect chasing back on — a `307` from the customer's own endpoint forwards the method
 * AND the body to whatever host it names, and the DNS pin was resolved for the first host,
 * not the second.
 */
final class SafeLegacyLoginUrl
{
    /**
     * HTTPS ONLY, and not negotiable on this plane.
     *
     * The hook transport lets an operator relax the scheme; here the payload is a password,
     * and "we logged a warning and sent it anyway" is a failure nobody reads until after.
     *
     * @var list<string>
     */
    private const SCHEMES = ['https'];

    /**
     * Guzzle options that pin the connection to the IPs just resolved.
     *
     * Redirects stay refused whether or not host verification is enforced — see the class
     * docblock, and {@see SafeWebhookUrl::pinnedOptions()}, which
     * holds the same line for the same reason.
     *
     * @return array<string, mixed>
     */
    public static function pinnedOptions(string $url): array
    {
        if (! UrlVerification::enforced('cbox-id.migration.verify_url')) {
            return ['allow_redirects' => false];
        }

        return ['allow_redirects' => false] + app(UrlGuard::class)->pinnedOptions($url, self::SCHEMES);
    }
}
