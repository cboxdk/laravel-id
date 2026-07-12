<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Support;

use Cbox\Id\Webhooks\Exceptions\UnsafeWebhookUrl;

/**
 * SSRF guard for outbound webhook URLs. A URL is only allowed when its scheme is
 * http(s) and EVERY address its host resolves to is a public unicast address —
 * blocking loopback, private (RFC 1918), link-local (incl. 169.254.169.254 cloud
 * metadata), and reserved ranges, for both IPv4 and IPv6.
 *
 * It is checked at registration AND immediately before each delivery, which
 * narrows (though a network-level egress allowlist is the complete answer to)
 * DNS-rebinding.
 */
final class SafeWebhookUrl
{
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
        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            throw UnsafeWebhookUrl::make('malformed URL');
        }

        $scheme = strtolower((string) $parts['scheme']);

        if (! in_array($scheme, ['http', 'https'], true)) {
            throw UnsafeWebhookUrl::make("scheme [{$scheme}] is not allowed");
        }

        $host = (string) $parts['host'];

        // No embedded credentials (user@host) — a common SSRF/obfuscation trick.
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw UnsafeWebhookUrl::make('credentials in URL are not allowed');
        }

        // A private/on-prem deployment can disable DNS/IP enforcement (e.g. to
        // deliver to internal hosts), and it is disabled in tests. Scheme and
        // credential checks above still apply. Default: full enforcement.
        if (config('cbox-id.webhooks.verify_url', true) !== true) {
            return;
        }

        $addresses = self::resolve($host);

        if ($addresses === []) {
            throw UnsafeWebhookUrl::make("host [{$host}] does not resolve");
        }

        foreach ($addresses as $ip) {
            if (! self::isPublic($ip)) {
                throw UnsafeWebhookUrl::make("resolves to a non-public address [{$ip}]");
            }
        }
    }

    /**
     * @return list<string>
     */
    private static function resolve(string $host): array
    {
        $host = trim($host, '[]'); // strip IPv6 brackets

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }

        $ips = [];

        $v4 = gethostbynamel($host);
        if (is_array($v4)) {
            $ips = $v4;
        }

        foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
            if (isset($record['ipv6']) && is_string($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }

        return array_values(array_unique($ips));
    }

    private static function isPublic(string $ip): bool
    {
        // Reject private + reserved ranges (loopback, link-local incl.
        // 169.254.169.254, RFC1918, unique-local fc00::/7, ::1, etc.).
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
    }
}
