<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Enums;

use Cbox\Id\Organization\Contracts\Organizations;

/**
 * The lifecycle state of an organization — and, via {@see self::revokesAccess()},
 * the access decision that travels with it.
 *
 * The decision lives HERE rather than in each host because the status alone is not
 * self-explaining: `Deleted` is written by {@see Organizations::archive()} and reads
 * like a soft-delete marker, but it must refuse authentication, consent and token
 * issuance exactly as `Suspended` does. A consumer that pattern-matched only on
 * `Suspended` kept authenticating the members of a "deleted" organization — so the
 * enum answers the question instead of every caller re-deriving it.
 */
enum OrganizationStatus: string
{
    case Active = 'active';
    case Suspended = 'suspended';
    case Deleted = 'deleted';

    /**
     * Whether an organization in this state must be refused access — sign-in,
     * consent, token issuance, and any other gate that speaks for its members.
     *
     * Deny-by-default: everything that is not `Active` revokes.
     *
     * The exhaustive `match` with NO `default` arm is the point of this method, not
     * an accident of style. A `default => false` — or a `!== Suspended` test at a
     * call site — is precisely how `Deleted` slipped through: a case added later
     * silently inherits "allowed". Without the arm, adding a case fails static
     * analysis at level max (`match.unhandled`) and the omission is caught before it
     * ships. Do not add a `default`.
     */
    public function revokesAccess(): bool
    {
        return match ($this) {
            self::Active => false,
            self::Suspended, self::Deleted => true,
        };
    }
}
