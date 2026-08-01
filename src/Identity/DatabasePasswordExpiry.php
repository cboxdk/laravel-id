<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\PasswordExpiry;
use Cbox\Id\Identity\Models\PasswordAge;
use Cbox\Id\Organization\Contracts\Memberships;

/**
 * The default {@see PasswordExpiry}: one `changed_at` row per subject, environment
 * scoped, compared against the effective policy's max age.
 */
class DatabasePasswordExpiry implements PasswordExpiry
{
    public function __construct(
        private readonly AuthPolicies $policies,
        private readonly Memberships $memberships,
    ) {}

    public function record(string $subjectId): void
    {
        PasswordAge::query()->updateOrCreate(
            ['user_id' => $subjectId],
            ['changed_at' => now()],
        );
    }

    public function hasExpired(string $subjectId, ?string $organizationId = null): bool
    {
        $maxAgeDays = $this->maxAgeFor($subjectId, $organizationId);

        if ($maxAgeDays === null) {
            return false;
        }

        $changedAt = PasswordAge::query()->where('user_id', $subjectId)->first()?->changed_at;

        // No record is not evidence of an old password — see the contract.
        return $changedAt !== null && $changedAt->addDays($maxAgeDays)->isPast();
    }

    /**
     * The shortest max age binding this subject.
     *
     * Same reasoning as the password policy guard: a caller that names an organization
     * gets that organization's, and a caller that does not — the sign-in gate, which
     * knows only a subject — gets the environment baseline tightened by every
     * organization the subject belongs to. A member of an organization demanding a
     * 30-day rotation does not get 180 because the request lacked org context.
     */
    private function maxAgeFor(string $subjectId, ?string $organizationId): ?int
    {
        if ($organizationId !== null) {
            return $this->policies->resolve($organizationId)->maxAgeDays;
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

        return $policy->maxAgeDays;
    }
}
