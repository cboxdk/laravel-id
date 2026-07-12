<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\TotpEnrollment;

interface Mfa
{
    /**
     * Begin TOTP enrolment: generate and store (sealed) a secret, returning it
     * and the provisioning URI once. Unconfirmed until the user proves a code.
     */
    public function enrollTotp(string $userId, string $account, string $issuer = 'Cbox ID'): TotpEnrollment;

    /**
     * Confirm enrolment by verifying the first code. Marks the factor confirmed.
     */
    public function confirmTotp(string $userId, string $code): bool;

    /**
     * Verify a code against a confirmed factor (e.g. at login step-up).
     */
    public function verifyTotp(string $userId, string $code): bool;

    public function hasConfirmedTotp(string $userId): bool;

    /**
     * (Re)generate the user's one-time recovery codes, replacing any existing
     * ones. Returns the plaintext codes exactly once — only hashes are stored.
     * Recovery codes are the escape hatch when the authenticator is lost.
     *
     * @return list<string>
     */
    public function generateRecoveryCodes(string $userId, int $count = 10): array;

    /**
     * Consume a recovery code as a second factor. Each code works once; returns
     * false for an unknown or already-used code. Constant-time per candidate.
     */
    public function verifyRecoveryCode(string $userId, string $code): bool;

    /**
     * How many unused recovery codes remain — for a "regenerate" nudge in the UI.
     */
    public function remainingRecoveryCodes(string $userId): int;
}
