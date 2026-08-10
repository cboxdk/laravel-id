<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi\Support;

/**
 * Turning what a person typed into the exact string a browser will send, or refusing.
 *
 * THE COMPARISON IS BYTE-FOR-BYTE, so everything hinges on both sides being written the
 * same way. A browser sends a SERIALIZED ORIGIN: lowercase scheme, lowercase host, port
 * only when it is not the scheme's default, and never a trailing slash or a path. A
 * person pastes `https://Acme.com/` or `acme.com` or `https://acme.com:443`. Those are
 * the same site and three different strings, and storing them as typed means an
 * allow-list that silently fails to match.
 *
 * So normalization happens ONCE, on the way in, and the stored value is what a browser
 * would send. Nothing at request time is lenient — leniency at request time is how
 * `https://acme.com.evil.test` gets in.
 *
 * `null` is a refusal, and the caller must surface it rather than storing the input. An
 * origin that cannot be normalized is one that would never have matched anything.
 */
final class Origin
{
    /** Ports a browser omits from a serialized origin. */
    private const DEFAULT_PORTS = ['http' => 80, 'https' => 443];

    /**
     * The serialized form of what a person typed, or null when it is not a usable origin.
     *
     * `http` is accepted alongside `https` because `http://localhost:3000` is where every
     * integration begins, and refusing it would mean the first thing a developer does is
     * hit an error they cannot fix. It is not accepted for anything else — see
     * {@see isLoopback()} and the caller that uses it.
     */
    public static function normalize(string $input): ?string
    {
        $input = trim($input);

        if ($input === '' || strlen($input) > 255) {
            return null;
        }

        // `null` is a real Origin header — a sandboxed iframe, a `file://` page, some
        // redirects — and it is never something we allow-list. Named here so it is
        // refused deliberately rather than by falling through the URL parser.
        if (strtolower($input) === 'null') {
            return null;
        }

        $parts = parse_url($input);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $scheme = strtolower($parts['scheme']);

        if (! array_key_exists($scheme, self::DEFAULT_PORTS)) {
            return null;
        }

        // A path, query or fragment means the person pasted a URL rather than an origin.
        // Silently trimming it would store something they did not check; refusing makes
        // them look at it. "/" alone is the exception — a browser address bar adds it.
        if (($parts['path'] ?? '/') !== '/' || isset($parts['query'], $parts['fragment'])) {
            return null;
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            return null;
        }

        $host = strtolower($parts['host']);

        if (! self::isPlausibleHost($host)) {
            return null;
        }

        $port = $parts['port'] ?? null;
        $origin = $scheme.'://'.$host;

        return $port !== null && $port !== self::DEFAULT_PORTS[$scheme]
            ? $origin.':'.$port
            : $origin;
    }

    /**
     * Whether an origin is a loopback address, where plain `http` is legitimate.
     *
     * Development happens on `http://localhost:3000`, and it is the one place a browser
     * treats an insecure origin as trustworthy. Everywhere else `http` means the key and
     * anything the page does with it crosses the network in the clear, so the console
     * refuses it — a permissive allow-list is not worth the one-line convenience.
     */
    public static function isLoopback(string $origin): bool
    {
        $host = parse_url($origin, PHP_URL_HOST);

        if (! is_string($host)) {
            return false;
        }

        return $host === 'localhost'
            || $host === '127.0.0.1'
            || $host === '[::1]'
            || str_ends_with($host, '.localhost');
    }

    /**
     * A host that could plausibly be resolved — letters, digits, hyphens and dots, or a
     * bracketed IPv6 literal.
     *
     * Not a validity oracle. It exists to keep obvious junk and anything with a control
     * character out of a string that will be echoed back in an
     * `Access-Control-Allow-Origin` header, where a newline would be a header injection.
     */
    private static function isPlausibleHost(string $host): bool
    {
        if (str_starts_with($host, '[')) {
            return (bool) preg_match('/^\[[0-9a-f:]+\]$/', $host);
        }

        return (bool) preg_match('/^[a-z0-9]([a-z0-9\-.]*[a-z0-9])?$/', $host)
            && ! str_contains($host, '..');
    }
}
