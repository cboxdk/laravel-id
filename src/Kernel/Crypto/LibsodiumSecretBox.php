<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Exceptions\CryptoConfigurationException;
use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;

/**
 * XChaCha20-Poly1305-IETF AEAD envelope encryption (libsodium).
 *
 * Each ciphertext carries its own random 24-byte nonce and an authentication
 * tag over both the plaintext and the `context` (additional authenticated
 * data). Tampering with any byte, or opening with a different context, fails.
 */
class LibsodiumSecretBox implements SecretBox
{
    public function __construct(private readonly string $key)
    {
        $expected = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

        if (strlen($this->key) !== $expected) {
            throw CryptoConfigurationException::invalidKeyLength($expected, strlen($this->key));
        }
    }

    public function seal(string $plaintext, string $context = ''): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $context,
            $nonce,
            $this->key,
        );

        return Base64Url::encode($nonce.$ciphertext);
    }

    public function open(string $ciphertext, string $context = ''): string
    {
        $raw = Base64Url::decode($ciphertext);
        $nonceLength = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

        if (strlen($raw) <= $nonceLength) {
            throw DecryptionFailed::malformed();
        }

        $nonce = substr($raw, 0, $nonceLength);
        $sealed = substr($raw, $nonceLength);

        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $sealed,
            $context,
            $nonce,
            $this->key,
        );

        if ($plaintext === false) {
            throw DecryptionFailed::forContext();
        }

        return $plaintext;
    }
}
