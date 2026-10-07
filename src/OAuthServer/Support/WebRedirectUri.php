<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

/**
 * The redirect-URI rule for a client that registered itself for a protected resource —
 * RFC 7591 registration in `mcp` mode, and a client ID metadata document: https on a real
 * host, or plain http on a loopback host (RFC 8252 §7.3, the CLI and desktop case).
 *
 * Narrower than what an operator may register, deliberately. No private-use schemes (an
 * anonymous registrant claiming `com.bank.app:/cb` is a phishing primitive), no fragment
 * (RFC 6749 §3.1.2), no credentials in the authority, and no sandbox http — the narrowest
 * set that still serves every MCP client shape.
 */
final class WebRedirectUri
{
    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]', '::1'];

    public static function isValid(string $uri): bool
    {
        $parts = parse_url($uri);

        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host']) || isset($parts['fragment'])
            || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);

        if ($scheme === 'https') {
            return $host !== '';
        }

        return $scheme === 'http' && in_array($host, self::LOOPBACK_HOSTS, true);
    }
}
