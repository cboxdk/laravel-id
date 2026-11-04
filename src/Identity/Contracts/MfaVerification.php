<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

/** Verification of a local sign-in is separate from enrolment of its factors. */
interface MfaVerification
{
    /**
     * Whether a local password or magic-link session still owes a second factor.
     * Federated authentication is governed by the upstream provider's policy.
     *
     * @param  list<string>  $amr
     */
    public function requiresVerification(string $subjectId, array $amr, ?string $organizationId = null): bool;
}
