<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Enums;

/**
 * What a directory may take away from a person it stops listing — a SCIM `DELETE`, an
 * `active: false`, or a pull sync that no longer sees them.
 *
 * The question is whose the account is. In an environment that belongs to one customer,
 * the directory IS the source of truth for who has an account, and a leaver must not be
 * able to sign back in: {@see Account}. In an environment many organizations share, the
 * account is the person's own and an organization only ever lent them a membership — so
 * one employer's directory must not be able to lock them out of every other organization
 * they belong to: {@see Membership}.
 */
enum DeprovisioningMode: string
{
    /**
     * Deactivate the account, drop the membership, end every session. The default, and
     * what every environment did before the mode existed.
     */
    case Account = 'account';

    /**
     * End this organization's membership and what was granted through it — its role
     * assignments, its refresh tokens, the sessions signed in to it — and nothing else.
     * The account is never deactivated, and never reactivated, by a directory.
     */
    case Membership = 'membership';

    /** Whether a directory in this mode may change the status of the account itself. */
    public function ownsAccount(): bool
    {
        return $this === self::Account;
    }
}
