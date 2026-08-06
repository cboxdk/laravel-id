<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Organization\Enums\MembershipRole;

/**
 * A role granted to a subject on a resource — the read-model shape of a
 * grant tuple, for listings and admin surfaces.
 */
readonly class AccessGrant
{
    public function __construct(
        public GrantSubject $subject,
        public MembershipRole $role,
        public ResourceRef $resource,
    ) {}
}
