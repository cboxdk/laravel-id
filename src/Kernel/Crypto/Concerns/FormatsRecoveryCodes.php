<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Concerns;

/**
 * Shared formatting/canonicalization for MFA recovery codes. Kept in one place
 * so every MFA subsystem (subject and operator) generates and verifies codes
 * with the SAME normalization — a divergence here would silently reject valid
 * recovery codes.
 */
trait FormatsRecoveryCodes
{
    /**
     * Group raw hex into a readable "xxxx-xxxx-xxxx-xxxx" code.
     */
    private function formatRecoveryCode(string $raw): string
    {
        return implode('-', str_split($raw, 4));
    }

    /**
     * Canonicalize user input before hashing: hyphens/spaces are cosmetic and the
     * comparison is case-insensitive.
     */
    private function normalizeRecoveryCode(string $code): string
    {
        return strtolower((string) preg_replace('/[^a-zA-Z0-9]/', '', $code));
    }
}
