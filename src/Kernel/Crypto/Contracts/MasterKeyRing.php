<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Contracts;

use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;

/**
 * The versioned view of the {@see SecretBox}: which master key generation sealed a given
 * ciphertext, and how to move it onto the current one.
 *
 * Kept apart from SecretBox on purpose. Every module that seals a secret needs only
 * seal/open and must not care that keys rotate; only the rewrap command and the doctor
 * ask these questions. A host that replaces SecretBox with its own (a KMS, an HSM) does
 * not have to implement rotation semantics it may handle elsewhere.
 */
interface MasterKeyRing
{
    /** The id of the key that seals everything new. */
    public function currentKeyId(): string;

    /**
     * The ids of the keys kept only to open older ciphertext.
     *
     * @return list<string>
     */
    public function previousKeyIds(): array;

    /**
     * The key id a ciphertext is tagged with, or null for an untagged envelope written
     * before key versioning existed (1.21 and earlier) — that one may be under any
     * configured key, and only opening it tells which.
     */
    public function sealedUnder(string $ciphertext): ?string;

    /** Whether a ciphertext is already sealed under the current key. */
    public function isCurrent(string $ciphertext): bool;

    /**
     * The literal prefix every ciphertext sealed under the current key starts with — so a
     * caller can count what is NOT yet current with one `NOT LIKE` per column instead of
     * reading every secret into PHP.
     */
    public function currentPrefix(): string;

    /**
     * Re-seal a ciphertext under the current key, with the same context. A ciphertext
     * already current is returned unchanged, so a rewrap can be re-run safely.
     *
     * @throws DecryptionFailed when no configured key opens it under that context
     */
    public function rewrap(string $ciphertext, string $context = ''): string;
}
