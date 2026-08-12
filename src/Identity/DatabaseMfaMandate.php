<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\MfaMandate;
use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Organization\Contracts\Memberships;

/**
 * The default {@see MfaMandate}: the effective policy's `mfa` field against the
 * subject's enrolled factors.
 */
class DatabaseMfaMandate implements MfaMandate
{
    public function __construct(
        private readonly AuthPolicies $policies,
        private readonly Memberships $memberships,
        private readonly Mfa $mfa,
    ) {}

    public function requiresEnrolment(string $subjectId, ?string $organizationId = null): bool
    {
        if ($this->effectiveRequirement($subjectId, $organizationId) !== MfaRequirement::Required) {
            return false;
        }

        if ($this->mfa->hasConfirmedTotp($subjectId)) {
            return false;
        }

        return ! WebAuthnCredential::query()->where('user_id', $subjectId)->exists();
    }

    public function offersEnrolment(string $subjectId, ?string $organizationId = null): bool
    {
        return $this->effectiveRequirement($subjectId, $organizationId) !== MfaRequirement::Off;
    }

    /**
     * The strictest requirement binding this subject — environment baseline tightened by
     * every organization they belong to, for the same reason the password policy resolves
     * that way: an organization that mandates a second factor does not lose it because
     * the caller had no org context to pass.
     */
    private function effectiveRequirement(string $subjectId, ?string $organizationId): MfaRequirement
    {
        if ($organizationId !== null) {
            return $this->policies->resolve($organizationId)->mfa;
        }

        $policy = $this->policies->forEnvironment();

        // One read for every organization the subject belongs to. Asking per membership
        // meant a query per organization on EVERY authenticated request — this method is
        // reached from the host's authentication middleware, which is also persistent
        // Livewire middleware, so it ran again on every round trip too.
        $organizationIds = array_values(array_map(
            fn ($membership): string => (string) $membership->organization_id,
            iterator_to_array($this->memberships->forUser($subjectId)),
        ));

        foreach ($this->policies->overridesFor($organizationIds) as $override) {
            $policy = $policy->tightenedWith($override);
        }

        return $policy->mfa;
    }
}
