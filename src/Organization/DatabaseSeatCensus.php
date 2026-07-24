<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Usage\Contracts\SeatCensus;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipStatus;

/**
 * The default {@see SeatCensus}: an ACTIVE membership occupies a seat. Living in the
 * Organization module keeps the Usage kernel free of any reference to memberships or
 * {@see MembershipStatus} — the kernel depends on the contract, and this module (which
 * owns the membership model) decides what counts as an occupied seat.
 */
class DatabaseSeatCensus implements SeatCensus
{
    public function __construct(private readonly Memberships $memberships) {}

    public function activeSeats(string $organizationId): int
    {
        return $this->memberships->forOrganization($organizationId)
            ->filter(fn ($membership): bool => $membership->status === MembershipStatus::Active)
            ->count();
    }
}
