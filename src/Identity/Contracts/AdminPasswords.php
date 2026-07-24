<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\AdminPasswordAssignment;

/**
 * Administrative credential management for subjects this platform owns.
 *
 * Distinct from {@see PasswordReset}, which is the SUBJECT proving control of their own
 * address. Here an administrator sets the credential directly — legitimate because the
 * user records are ours, and safe only because every call is authorized by the caller,
 * recorded on the tamper-evident audit log, and (at the administrator's choice) revokes
 * the access the previous credential held.
 */
interface AdminPasswords
{
    /**
     * Replace a subject's password on an administrator's authority, applying the
     * assignment's change-required flag, expiry and revocation scope, and recording an
     * `identity.password_set_by_admin` audit event.
     *
     * Authorization is the CALLER's responsibility — this contract performs the act, it
     * does not decide who may perform it.
     */
    public function assign(AdminPasswordAssignment $assignment): void;

    /**
     * Whether the subject must choose a new password before proceeding. The sign-in
     * flow consults this after the credential itself verifies.
     */
    public function requiresChange(string $userId): bool;

    /**
     * Whether an administratively-issued temporary password has passed its expiry and
     * must no longer authenticate at all.
     */
    public function hasExpired(string $userId): bool;

    /**
     * Clear the standing requirement — called once the subject has chosen their own
     * password.
     */
    public function clear(string $userId): void;
}
