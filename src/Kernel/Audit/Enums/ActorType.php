<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Enums;

/**
 * Who performed an audited action.
 *
 * `OrganizationMember` was `AccountMember`, naming the plane that owned the management
 * console before an account became an organization. It stays distinct from `User`, and the
 * distinction is why both exist: a `User` is an end user inside a tenant's own environment,
 * while an `OrganizationMember` is one of the CUSTOMER's own people acting on the
 * management plane — creating environments, minting keys, inviting colleagues. Collapsing
 * the two would make "who did this" unanswerable for exactly the actions a customer is
 * most likely to be asked about later.
 *
 * The STORED value changes with the case, and no deployment carries the old one across:
 * production is rebuilt with `migrate:fresh`, and this is the last release in which
 * changing a persisted enum value costs nothing.
 */
enum ActorType: string
{
    case User = 'user';
    case Service = 'service';
    case System = 'system';
    case Operator = 'operator';
    case OrganizationMember = 'organization_member';
}
