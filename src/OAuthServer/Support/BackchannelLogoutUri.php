<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;

/**
 * What a `backchannel_logout_uri` may be (Back-Channel Logout 1.0 §2.2).
 *
 * The spec: an absolute URI, which MAY carry a query and MUST NOT carry a fragment. The
 * policy on top of it, in the same style as redirect URIs: HTTPS, with plain HTTP only on
 * a loopback host for local development.
 *
 * HTTPS because the request carries a signed statement about a named person, and because
 * a relying party verifies the token but cannot verify who it came from over plaintext. A
 * loopback URI registers but will not be CALLED while the delivery-time SSRF guard is on
 * — that guard refuses loopback addresses by design — so local development switches the
 * guard off (`cbox-id.oauth.backchannel_logout.verify_url`), never this check.
 *
 * Checked at registration; the destination is checked again, with DNS pinned, at
 * delivery ({@see SafeBackchannelLogoutUrl}), because a hostname that was public when it
 * was registered can point anywhere by the time somebody signs out.
 */
class BackchannelLogoutUri
{
    /** Registration never needs more, and the column holds exactly this much. */
    public const MAX_LENGTH = 2048;

    /**
     * @throws InvalidClientMetadata
     */
    public static function assertValid(string $uri): void
    {
        if (strlen($uri) > self::MAX_LENGTH) {
            throw InvalidClientMetadata::metadata('backchannel_logout_uri must be at most '.self::MAX_LENGTH.' characters');
        }

        $parts = parse_url($uri);

        if ($parts === false || ! isset($parts['scheme'], $parts['host']) || $parts['host'] === '') {
            throw InvalidClientMetadata::metadata("backchannel_logout_uri is not an absolute URI: {$uri}");
        }

        if (isset($parts['fragment']) || str_contains($uri, '#')) {
            throw InvalidClientMetadata::metadata("backchannel_logout_uri must not contain a fragment: {$uri}");
        }

        // Credentials in the authority are a way to smuggle a second host past a reader
        // (`https://trusted.example@evil.example/`), and a logout endpoint has no use for them.
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw InvalidClientMetadata::metadata("backchannel_logout_uri must not contain credentials: {$uri}");
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower(trim($parts['host'], '[]'));

        if ($scheme === 'https') {
            return;
        }

        if ($scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
            return;
        }

        throw InvalidClientMetadata::metadata("backchannel_logout_uri must use https (or http on localhost): {$uri}");
    }
}
