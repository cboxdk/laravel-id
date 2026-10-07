<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

/**
 * The shape a `client_id` must have to be a client ID metadata document URL
 * (draft-ietf-oauth-client-id-metadata-document §3): https, a host, a path that is more
 * than `/`, no single- or double-dot path segments, no fragment, no credentials.
 *
 * Checked BEFORE anything is fetched, so a `client_id` that is not one of these is never
 * a reason for the server to make a request — the rule is the first wall, the SSRF guard
 * the second. Capped at 255 characters because the client id is stored on every code,
 * token and grant row, and those columns are that wide.
 */
final class ClientIdUrl
{
    public const MAX_LENGTH = 255;

    public static function isValid(string $clientId): bool
    {
        if ($clientId === '' || strlen($clientId) > self::MAX_LENGTH || trim($clientId) !== $clientId) {
            return false;
        }

        $parts = parse_url($clientId);

        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host'])
            || strtolower($parts['scheme']) !== 'https'
            || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }

        $path = $parts['path'] ?? '';

        if ($path === '' || $path === '/') {
            return false;
        }

        foreach (explode('/', $path) as $segment) {
            if ($segment === '.' || $segment === '..') {
                return false;
            }
        }

        return filter_var($clientId, FILTER_VALIDATE_URL) !== false;
    }

    /**
     * The host a consent screen shows: the one thing about a metadata document client
     * that is actually verified — whoever controls this host published the document.
     */
    public static function host(string $clientId): string
    {
        $host = parse_url($clientId, PHP_URL_HOST);

        return is_string($host) ? strtolower($host) : '';
    }
}
