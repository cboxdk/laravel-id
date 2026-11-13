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

    /** The loopback hosts exactly as parse_url() returns them for a canonical URI. */
    private const CANONICAL_LOOPBACK_HOSTS = ['127.0.0.1', '[::1]', 'localhost'];

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

    /**
     * Whether $uri is an http loopback URI in canonical form — the only shape that may take
     * the loopback port exception (RFC 8252 §7.3). See {@see loopbackWithoutPort()}.
     */
    public static function isCanonicalLoopback(string $uri): bool
    {
        return self::loopbackWithoutPort($uri) !== null;
    }

    /**
     * $uri with its port removed, when it is an http loopback URI in canonical form; null
     * otherwise. Every loopback port comparison goes through this one matcher.
     *
     * Canonical means byte-identical to `http://host[:port]path[?query]` rebuilt from its
     * own parse, with the host exactly `127.0.0.1`, `[::1]` or `localhost`. parse_url() and
     * a browser's URL parser disagree on some authorities: a backslash ends the authority
     * for a browser but not for PHP, credentials before `@` hide the host a reader sees,
     * and parse_url() rewrites control characters. Where the two disagree, a port match on
     * the host PHP saw says nothing about where the browser, and the authorization code,
     * will go. So: no control character, whitespace or backslash, no credentials, no
     * fragment, a lower-case `http` scheme, and nothing the rebuild would change. A URI
     * that fails this can still be accepted, but only by an exact match.
     */
    public static function loopbackWithoutPort(string $uri): ?string
    {
        if (preg_match('/[\x00-\x20\x7f\\\\]/', $uri) === 1) {
            return null;
        }

        $parts = parse_url($uri);

        if (! is_array($parts) || ($parts['scheme'] ?? null) !== 'http'
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || ! in_array($parts['host'] ?? null, self::CANONICAL_LOOPBACK_HOSTS, true)) {
            return null;
        }

        $path = ($parts['path'] ?? '').(isset($parts['query']) ? '?'.$parts['query'] : '');
        $port = isset($parts['port']) ? ':'.$parts['port'] : '';

        if ('http://'.$parts['host'].$port.$path !== $uri) {
            return null;
        }

        return 'http://'.$parts['host'].$path;
    }
}
