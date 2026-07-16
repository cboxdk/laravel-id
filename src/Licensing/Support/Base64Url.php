<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing\Support;

/**
 * URL-safe base64 without padding — the encoding for a license token's segments.
 */
final class Base64Url
{
    public static function encode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    /**
     * Decode a URL-safe base64 string, or null if it isn't valid base64.
     */
    public static function decode(string $encoded): ?string
    {
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }
}
