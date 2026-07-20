<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Support;

use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;

/**
 * RFC 7515 base64url (unpadded) encoding — the encoding used throughout JOSE.
 */
class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode(string $data): string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        if ($decoded === false) {
            throw DecryptionFailed::malformed();
        }

        return $decoded;
    }
}
