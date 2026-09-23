<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

/**
 * RFC 8707 §2's shape for a resource indicator: an absolute URI with a host and no
 * fragment. The same rule the token endpoint applies to a requested `resource`, so an API
 * can only be registered under an identifier a client is able to ask for.
 */
final class ResourceIndicator
{
    public const MAX_LENGTH = 255;

    public static function isWellFormed(string $resource): bool
    {
        if ($resource === '' || strlen($resource) > self::MAX_LENGTH || trim($resource) !== $resource) {
            return false;
        }

        $parts = parse_url($resource);

        return is_array($parts)
            && isset($parts['scheme'], $parts['host'])
            && ! isset($parts['fragment'])
            && filter_var($resource, FILTER_VALIDATE_URL) !== false;
    }
}
