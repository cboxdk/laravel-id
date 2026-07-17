<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Kernel\Crypto\ValueObjects\TotpEnrollment;

/**
 * TOTP second factor + recovery codes for account members — the buyer plane's
 * counterpart of {@see OperatorMfa}. A separate subsystem keyed by member id, so a
 * member's factor is never confused with an operator's or a tenant user's.
 */
interface AccountMemberMfa
{
    /**
     * Begin TOTP enrolment: generate and store (sealed) a secret, returning it and
     * the provisioning URI once. Unconfirmed until the member proves a code.
     */
    public function enrollTotp(string $memberId, string $account, string $issuer = 'Cbox ID'): TotpEnrollment;

    /** Confirm enrolment by verifying the first code. Marks the factor confirmed. */
    public function confirmTotp(string $memberId, string $code): bool;

    /** Verify a code against a confirmed factor (login step-up). */
    public function verifyTotp(string $memberId, string $code): bool;

    public function hasConfirmedTotp(string $memberId): bool;

    /** Remove the member's TOTP factor and any remaining recovery codes. */
    public function disable(string $memberId): void;

    /**
     * (Re)generate one-time recovery codes, replacing any existing ones. Returns
     * the plaintext codes exactly once — only hashes are stored.
     *
     * @return list<string>
     */
    public function generateRecoveryCodes(string $memberId, int $count = 10): array;

    /**
     * Consume a recovery code as a second factor. Each works once; returns false
     * for an unknown or already-used code. Constant-time per candidate.
     */
    public function verifyRecoveryCode(string $memberId, string $code): bool;

    /** How many unused recovery codes remain. */
    public function remainingRecoveryCodes(string $memberId): int;
}
