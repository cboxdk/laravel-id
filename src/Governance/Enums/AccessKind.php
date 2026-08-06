<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Enums;

/**
 * The kind of access grant a certification item reviews. v1 governs the two
 * subject-centric, cleanly enumerable-and-revocable grants: RBAC role assignments
 * and organization memberships. (Entitlements are billing-fed projections governed
 * at their source; ReBAC tuples lack an enumeration/audit surface — both are out of
 * scope for v1, see docs/security/governance.md.)
 */
enum AccessKind: string
{
    case Role = 'role';
    case Membership = 'membership';
}
