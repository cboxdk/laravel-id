<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;

/**
 * Whether a subject still owes the tenant a second factor.
 *
 * {@see AuthPolicy::$mfa} is the only field of the policy that cannot be enforced by
 * refusing something: turning away a subject who has no factor, on a policy that has
 * just started requiring one, locks out exactly the people who need to enrol. So the
 * mandate is expressed as a question — "does this subject owe one?" — and the host holds
 * them at enrolment until the answer is no.
 */
interface MfaMandate
{
    /**
     * True when the effective policy is {@see MfaRequirement::Required} and the subject
     * has no second factor enrolled.
     *
     * A confirmed TOTP factor and a registered passkey both count. A passkey is usually
     * the STRONGER of the two — phishing-resistant, hardware-bound — so treating it as
     * not-a-factor would push people from a better credential to a worse one to satisfy
     * a policy meant to raise the bar.
     */
    public function requiresEnrolment(string $subjectId, ?string $organizationId = null): bool;
}
