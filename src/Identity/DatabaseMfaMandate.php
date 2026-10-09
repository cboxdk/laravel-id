<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\MfaMandate;
use Cbox\Id\Identity\Contracts\SmsFactors;
use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Organization\Contracts\Memberships;

/**
 * The default {@see MfaMandate}: the effective policy's `mfa` field against the
 * subject's enrolled factors.
 *
 * An SMS factor counts only while the environment's SMS policy accepts it — and never as
 * an administrator's ONLY factor when the policy says so: such a person is asked to enrol
 * an authenticator app or a passkey even where the second factor is otherwise optional,
 * because that is what "SMS cannot be an administrator's only factor" means once they
 * already hold it. The SMS dependency is optional so a host constructing this class
 * itself is unaffected.
 */
class DatabaseMfaMandate implements MfaMandate
{
    public function __construct(
        private readonly AuthPolicies $policies,
        private readonly Memberships $memberships,
        private readonly Mfa $mfa,
        private readonly ?SmsFactors $sms = null,
    ) {}

    public function requiresEnrolment(string $subjectId, ?string $organizationId = null): bool
    {
        $requirement = $this->effectiveRequirement($subjectId, $organizationId);

        if ($requirement !== MfaRequirement::Off && $this->sms?->needsStrongerFactor($subjectId) === true) {
            return true;
        }

        if ($requirement !== MfaRequirement::Required) {
            return false;
        }

        if ($this->mfa->hasConfirmedTotp($subjectId)) {
            return false;
        }

        if ($this->sms?->isUsable($subjectId) === true) {
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
