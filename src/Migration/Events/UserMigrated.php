<?php

declare(strict_types=1);

namespace Cbox\Id\Migration\Events;

use Cbox\Id\Identity\ValueObjects\ImportedUser;
use Cbox\Id\Identity\ValueObjects\Subject;

/**
 * A person moved off the old system, at the moment they signed in.
 *
 * Carries BOTH sides on purpose: the subject as this platform now knows them, and the
 * record as the old system described them. A host attaching the person to an organization
 * needs the second — the role, the tenant, whatever the legacy row carried that has no
 * column here — and would otherwise have to go back and ask the source again, which by
 * then may need a password it does not have.
 */
final readonly class UserMigrated
{
    public function __construct(
        public Subject $subject,
        public ImportedUser $legacy,
    ) {}
}
