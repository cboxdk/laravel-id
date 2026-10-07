<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

use Cbox\Id\Kernel\Crypto\Contracts\MasterKeyRing;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Crypto\ValueObjects\MasterKey;
use Cbox\Id\Kernel\Crypto\ValueObjects\MasterKeySet;
use SensitiveParameter;

/**
 * XChaCha20-Poly1305-IETF AEAD envelope encryption (libsodium), over a versioned keyring.
 *
 * Each ciphertext carries its own random 24-byte nonce and an authentication tag over
 * both the plaintext and the `context` (additional authenticated data). Tampering with
 * any byte, or opening with a different context, fails.
 *
 * ## Envelope formats
 *
 * - **v1 (since 1.22)** — `v1.<key-id>.<base64url(nonce ‖ ciphertext ‖ tag)>`. The key id
 *   is {@see MasterKey::$id}, a stable digest of the key, never the key. Opening uses
 *   exactly the key the envelope names, and an unknown id fails with a message that says
 *   which key to configure.
 * - **untagged (1.21 and earlier)** — `base64url(nonce ‖ ciphertext ‖ tag)`, no prefix.
 *   Still opened, forever: every configured key is tried, current first. These never
 *   contain a `.`, which base64url cannot produce, so the two formats cannot be confused.
 *
 * Everything new is sealed v1 under the CURRENT key; `cbox-id:crypto:rewrap` moves
 * older envelopes onto it. The frozen-envelope tests pin both formats.
 */
class LibsodiumSecretBox implements MasterKeyRing, SecretBox
{
    private const VERSION = 'v1';

    private MasterKeySet $keys;

    /**
     * @param  string|MasterKeySet  $keys  the keyring, or — as before 1.22 — a single raw
     *                                     32-byte key, which becomes a ring of one
     */
    public function __construct(#[SensitiveParameter] string|MasterKeySet $keys)
    {
        $this->keys = is_string($keys) ? new MasterKeySet(new MasterKey($keys)) : $keys;
    }

    public function seal(string $plaintext, string $context = ''): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $context,
            $nonce,
            $this->keys->current->bytes(),
        );

        return $this->currentPrefix().Base64Url::encode($nonce.$ciphertext);
    }

    public function open(string $ciphertext, string $context = ''): string
    {
        if (! str_contains($ciphertext, '.')) {
            return $this->openUntagged($ciphertext, $context);
        }

        [$keyId, $payload] = $this->parseTagged($ciphertext);

        $key = $this->keys->find($keyId);

        if ($key === null) {
            throw DecryptionFailed::unknownKey($keyId);
        }

        $plaintext = $this->decrypt($payload, $context, $key);

        if ($plaintext === null) {
            throw DecryptionFailed::forContext();
        }

        return $plaintext;
    }

    public function currentKeyId(): string
    {
        return $this->keys->current->id;
    }

    public function previousKeyIds(): array
    {
        return $this->keys->previousIds();
    }

    public function sealedUnder(string $ciphertext): ?string
    {
        if (! str_contains($ciphertext, '.')) {
            return null;
        }

        return $this->parseTagged($ciphertext)[0];
    }

    public function isCurrent(string $ciphertext): bool
    {
        return str_starts_with($ciphertext, $this->currentPrefix());
    }

    public function currentPrefix(): string
    {
        return self::VERSION.'.'.$this->keys->current->id.'.';
    }

    public function rewrap(string $ciphertext, string $context = ''): string
    {
        if ($this->isCurrent($ciphertext)) {
            return $ciphertext;
        }

        return $this->seal($this->open($ciphertext, $context), $context);
    }

    /**
     * An envelope from before key versioning: it does not say which key sealed it, so try
     * each configured one, current first. Only the AEAD tag decides — a wrong key simply
     * fails authentication — so this can never return a plaintext under the wrong key.
     */
    private function openUntagged(string $ciphertext, string $context): string
    {
        $raw = Base64Url::decode($ciphertext);

        foreach ($this->keys->all() as $key) {
            $plaintext = $this->decryptRaw($raw, $context, $key);

            if ($plaintext !== null) {
                return $plaintext;
            }
        }

        throw DecryptionFailed::forContext();
    }

    /**
     * @return array{0: string, 1: string} the key id and the base64url payload
     */
    private function parseTagged(string $ciphertext): array
    {
        $parts = explode('.', $ciphertext, 3);

        if (count($parts) !== 3 || $parts[1] === '' || $parts[2] === '') {
            throw DecryptionFailed::malformed();
        }

        if ($parts[0] !== self::VERSION) {
            throw DecryptionFailed::unsupportedVersion();
        }

        return [$parts[1], $parts[2]];
    }

    private function decrypt(string $payload, string $context, MasterKey $key): ?string
    {
        return $this->decryptRaw(Base64Url::decode($payload), $context, $key);
    }

    private function decryptRaw(string $raw, string $context, MasterKey $key): ?string
    {
        $nonceLength = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

        if (strlen($raw) <= $nonceLength) {
            throw DecryptionFailed::malformed();
        }

        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            substr($raw, $nonceLength),
            $context,
            substr($raw, 0, $nonceLength),
            $key->bytes(),
        );

        return $plaintext === false ? null : $plaintext;
    }
}
