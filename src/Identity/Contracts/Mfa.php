<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Kernel\Crypto\ValueObjects\TotpEnrollment;

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

    /**
     * Remove the user's second factor entirely — every enrolled factor and every
     * recovery code — so their next sign-in enrolls afresh.
     *
     * This exists because an administrator has to be able to help someone who has lost
     * their authenticator, and because doing it WITHOUT a verb here meant doing it with
     * raw model deletes: the host console did exactly that, so the single most
     * privileged MFA mutation in the platform was the only one that left no audit
     * entry, no domain event and no usage record. The account and operator planes have
     * had this verb from the start.
     */
    public function disable(string $userId): void;
}
