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
}
