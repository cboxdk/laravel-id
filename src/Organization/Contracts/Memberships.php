<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\Organization\Models\Membership;

interface Memberships
{
    public function add(string $organizationId, string $userId, string $role, ?string $invitedBy = null): Membership;

    public function changeRole(string $organizationId, string $userId, string $role): Membership;

    public function remove(string $organizationId, string $userId): void;

    public function of(string $organizationId, string $userId): ?Membership;
}
