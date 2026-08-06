<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\WebAuthn;

use Cbox\Id\Identity\Exceptions\UnsupportedCredential;

/**
 * Converts a decoded COSE_Key (RFC 8152) into a PEM SubjectPublicKeyInfo that
 * OpenSSL can verify against. Only the ASN.1/DER *serialization* lives here —
 * the actual signature verification is done by OpenSSL, never by hand.
 *
 * Supported key types: EC2 / P-256 (ES256, `alg -7`) and RSA (RS256, `alg -257`),
 * which together cover Apple, Android, Windows Hello and the major security keys.
 */
class CoseKey
{
    // COSE key-type and algorithm identifiers (RFC 8152 / IANA COSE registry).
    private const KTY_EC2 = 2;

    private const KTY_RSA = 3;

    private const ALG_ES256 = -7;

    private const ALG_RS256 = -257;

    private const CRV_P256 = 1;

    /**
     * @param  array<int|string, mixed>  $cose  a normalized COSE_Key map
     */
    public static function toPem(array $cose): string
    {
        return match (self::int($cose, 1)) {
            self::KTY_EC2 => self::ec2ToPem($cose),
            self::KTY_RSA => self::rsaToPem($cose),
            default => throw UnsupportedCredential::make('unsupported COSE key type'),
        };
    }

    /**
     * @param  array<int|string, mixed>  $cose
     */
    private static function ec2ToPem(array $cose): string
    {
        if (self::int($cose, 3) !== self::ALG_ES256) {
            throw UnsupportedCredential::make('unsupported EC algorithm (expected ES256)');
        }

        if (self::int($cose, -1) !== self::CRV_P256) {
            throw UnsupportedCredential::make('unsupported EC curve (expected P-256)');
        }

        $x = str_pad(self::bytes($cose, -2), 32, "\0", STR_PAD_LEFT);
        $y = str_pad(self::bytes($cose, -3), 32, "\0", STR_PAD_LEFT);

        // Fixed SubjectPublicKeyInfo prefix for id-ecPublicKey over prime256v1,
        // followed by the uncompressed point (0x04 || X || Y).
        $spki = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200')."\x04".$x.$y;

        return self::pem($spki);
    }

    /**
     * @param  array<int|string, mixed>  $cose
     */
    private static function rsaToPem(array $cose): string
    {
        if (self::int($cose, 3) !== self::ALG_RS256) {
            throw UnsupportedCredential::make('unsupported RSA algorithm (expected RS256)');
        }

        $rsaPublicKey = self::seq(
            self::integer(self::bytes($cose, -1)).self::integer(self::bytes($cose, -2)),
        );

        // AlgorithmIdentifier { rsaEncryption, NULL }
        $algId = hex2bin('300d06092a864886f70d0101010500');

        $spki = self::seq($algId.self::bitString($rsaPublicKey));

        return self::pem($spki);
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(base64_encode($der), 64, "\n")
            .'-----END PUBLIC KEY-----'."\n";
    }

    // --- minimal DER writers ------------------------------------------------

    private static function seq(string $content): string
    {
        return "\x30".self::len($content).$content;
    }

    private static function bitString(string $content): string
    {
        return "\x03".self::len("\x00".$content)."\x00".$content;
    }

    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\0");

        if ($bytes === '') {
            $bytes = "\0";
        }

        // Prepend 0x00 if the high bit is set, so it stays a positive integer.
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\0".$bytes;
        }

        return "\x02".self::len($bytes).$bytes;
    }

    private static function len(string $content): string
    {
        $length = strlen($content);

        if ($length < 128) {
            return chr($length);
        }

        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xFF).$bytes;
            $length >>= 8;
        }

        return chr(0x80 | (strlen($bytes) & 0x7F)).$bytes;
    }

    // --- typed accessors over the normalized COSE map -----------------------

    /**
     * @param  array<int|string, mixed>  $cose
     */
    private static function int(array $cose, int $label): int
    {
        $value = $cose[$label] ?? $cose[(string) $label] ?? null;

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && $value !== '' && preg_match('/^-?\d+$/', $value) === 1) {
            return (int) $value;
        }

        throw UnsupportedCredential::make("COSE label {$label} is not an integer");
    }

    /**
     * @param  array<int|string, mixed>  $cose
     */
    private static function bytes(array $cose, int $label): string
    {
        $value = $cose[$label] ?? $cose[(string) $label] ?? null;

        if (! is_string($value) || $value === '') {
            throw UnsupportedCredential::make("COSE label {$label} is not a byte string");
        }

        return $value;
    }
}
