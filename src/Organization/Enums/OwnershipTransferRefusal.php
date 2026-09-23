<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Enums;

/**
 * Why an ownership transfer was refused — machine-readable, so an API can answer with a
 * stable error code and a console can show the right sentence, rather than both parsing
 * an exception message.
 */
enum OwnershipTransferRefusal: string
{
    /** The person handing the organization over is not an active owner of it. */
    case NotOwner = 'not_owner';

    /** The person receiving it is not a member of the organization. */
    case TargetNotMember = 'target_not_member';

    /** The person receiving it is a member, but not an active one (invited or suspended). */
    case TargetNotActive = 'target_not_active';

    /** Both sides are the same person. */
    case SameMember = 'same_member';
}
