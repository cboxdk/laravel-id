<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\ValueObjects;

use Cbox\Id\Kernel\Crypto\Exceptions\CryptoConfigurationException;
use Cbox\Id\Kernel\Crypto\LibsodiumSecretBox;
use SensitiveParameter;

/**
 * One generation of the SecretBox master key, and the short public id it is known by.
 *
 * THE ID IS DERIVED, NEVER STORED BESIDE THE KEY. It is the first 16 hex characters of
 * HMAC-SHA256 keyed with the master key over a fixed label — a PRF output, so it says
 * nothing about the key, yet it is stable: the same key always has the same id, on every
 * process and every host, with nothing to keep in sync. That is what lets a ciphertext
 * carry its key generation (see {@see LibsodiumSecretBox}) and a
 * decryptor find the right key after a rotation without a key table or a version counter
 * that could drift from the configuration.
 *
 * 64 bits is ample: a deployment holds a handful of generations at once, and a
 * collision would only cost a failed decrypt attempt before the right key is tried.
 *
 * The raw bytes stay private and out of `var_dump()` / exception traces.
 */
readonly class MasterKey
{
    /** Domain separation for the id derivation — never reuse this label for anything else. */
    private const ID_LABEL = 'cbox-id/secretbox/key-id/v1';

    /** Hex characters of the HMAC kept as the id. */
    private const ID_LENGTH = 16;

    public string $id;

    private string $bytes;

    public function __construct(#[SensitiveParameter] string $bytes)
    {
        $expected = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

        if (strlen($bytes) !== $expected) {
            throw CryptoConfigurationException::invalidKeyLength($expected, strlen($bytes));
        }

        $this->bytes = $bytes;
        $this->id = substr(hash_hmac('sha256', self::ID_LABEL, $bytes), 0, self::ID_LENGTH);
    }

    /**
     * Parse a configured key: base64, with or without Laravel's `base64:` prefix (the
     * convention operators reach for by muscle memory from `APP_KEY`). Null for an
     * empty or undecodable value, so the caller decides which error that is.
     */
    public static function tryFromConfigured(#[SensitiveParameter] mixed $configured): ?self
    {
        if (! is_string($configured)) {
            return null;
        }

        $configured = trim($configured);

        if (str_starts_with($configured, 'base64:')) {
            $configured = substr($configured, 7);
        }

        if ($configured === '') {
            return null;
        }

        $decoded = base64_decode($configured, true);

        return $decoded === false ? null : new self($decoded);
    }

    /** The raw 32 key bytes — for the AEAD call and nothing else. */
    public function bytes(): string
    {
        return $this->bytes;
    }

    /** @return array{id: string} */
    public function __debugInfo(): array
    {
        return ['id' => $this->id];
    }
}
