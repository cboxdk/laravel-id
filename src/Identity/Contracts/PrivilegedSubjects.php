<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\MembershipPrivilegedSubjects;

/**
 * Who counts as an ADMINISTRATOR for factor-strength rules — today, "SMS cannot be an
 * administrator's only second factor".
 *
 * The default ({@see MembershipPrivilegedSubjects}) answers yes for an owner or admin of
 * any organization. A host with its own notion of an administrator (environment
 * operators, a staff flag) binds its own — and should include the default's answer.
 */
interface PrivilegedSubjects
{
    public function isPrivileged(string $subjectId): bool;
}
