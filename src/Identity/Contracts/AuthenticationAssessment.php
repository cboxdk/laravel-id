<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Exceptions\AuthenticationStepUpRequired;
use Cbox\Id\Identity\ValueObjects\VerifiedAuthentication;

/** Optional host risk policy, after credential verification and before issuance. */
interface AuthenticationAssessment
{
    /**
     * Return only when ordinary ID policy may continue. An unavailable assessment is
     * not a successful authentication: the host owns its bounded fallback policy.
     * Implementations must use a bounded deadline and must never weaken ID's MFA,
     * subject, organization, freshness or grant checks. No credentials are supplied.
     *
     * @throws AuthenticationStepUpRequired when stronger authentication is required
     */
    public function assertAllowed(VerifiedAuthentication $authentication): void;
}
