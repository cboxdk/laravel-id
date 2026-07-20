<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Testing;

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;

/**
 * In-memory {@see SecretBox} for tests — no libsodium, no master key. It still
 * enforces the real contract's context binding (open() with the wrong context
 * throws {@see DecryptionFailed}), so tests exercise the same failure modes
 * without real crypto. NEVER use outside tests: the "ciphertext" is reversible.
 */
class FakeSecretBox implements SecretBox
{
    public function seal(string $plaintext, string $context = ''): string
    {
        return 'fake:'.base64_encode($context)."\0".base64_encode($plaintext);
    }

    public function open(string $ciphertext, string $context = ''): string
    {
        if (! str_starts_with($ciphertext, 'fake:') || ! str_contains($ciphertext, "\0")) {
            throw new DecryptionFailed('Not a FakeSecretBox ciphertext.');
        }

        [$sealedContext, $sealedPlaintext] = explode("\0", substr($ciphertext, 5), 2);

        // The context is authenticated data — a mismatch fails, exactly as the
        // real AEAD would.
        if (! hash_equals(base64_decode($sealedContext), $context)) {
            throw new DecryptionFailed('Context mismatch.');
        }

        return (string) base64_decode($sealedPlaintext);
    }
}
