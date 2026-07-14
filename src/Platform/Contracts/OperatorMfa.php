<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Kernel\Crypto\ValueObjects\TotpEnrollment;

/**
 * TOTP second factor for platform operators — the control-plane counterpart of
 * the subject-facing {@see Mfa}. Deliberately a
 * separate subsystem keyed by operator id (operators are not environment-owned
 * subjects), so an operator's factor is never confused with a tenant user's.
 */
interface OperatorMfa
{
    /**
     * Begin TOTP enrolment: generate and store (sealed) a secret, returning it
     * and the provisioning URI once. Unconfirmed until the operator proves a code.
     */
    public function enrollTotp(string $operatorId, string $account, string $issuer = 'Cbox ID'): TotpEnrollment;

    /**
     * Confirm enrolment by verifying the first code. Marks the factor confirmed.
     */
    public function confirmTotp(string $operatorId, string $code): bool;

    /**
     * Verify a code against a confirmed factor (e.g. at operator login step-up).
     */
    public function verifyTotp(string $operatorId, string $code): bool;

    public function hasConfirmedTotp(string $operatorId): bool;

    /**
     * Remove the operator's TOTP factor and any remaining recovery codes.
     */
    public function disable(string $operatorId): void;

    /**
     * (Re)generate the operator's one-time recovery codes, replacing any existing
     * ones. Returns the plaintext codes exactly once — only hashes are stored.
     *
     * @return list<string>
     */
    public function generateRecoveryCodes(string $operatorId, int $count = 10): array;

    /**
     * Consume a recovery code as a second factor. Each code works once; returns
     * false for an unknown or already-used code. Constant-time per candidate.
     */
    public function verifyRecoveryCode(string $operatorId, string $code): bool;

    /**
     * How many unused recovery codes remain — for a "regenerate" nudge in the UI.
     */
    public function remainingRecoveryCodes(string $operatorId): int;
}
