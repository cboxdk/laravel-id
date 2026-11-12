<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\FeatureFlags\Support\FeatureFlagClaim;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Cbox\Id\Organization\Models\Membership;

/**
 * The claims that describe a person to the client that signed them in: who they are, the
 * organization the grant is bound to, what they may do in this app, and the organizations
 * they belong to.
 *
 * ONE SOURCE FOR TWO ANSWERS. UserInfo returns exactly these beside `sub`, and the ID Token
 * carries exactly these beside its protocol claims, so a relying party that reads the ID
 * Token and skips the UserInfo call gets the same answer. A claim added here reaches both;
 * a claim added to only one of them is the bug this class exists to prevent (a client that
 * skips UserInfo takes everything from the ID Token, so an ID Token with `email` and no
 * `roles` signs a person in without their roles).
 *
 * What each claim needs:
 *
 *  - `email`, `email_verified`: the `email` scope, and a subject that has an address;
 *  - `name`: the `profile` scope, and a subject that has a name;
 *  - `org`, `org_slug`, `org_name`, `org_role`: a grant bound to an organization. `org_role`
 *    only while the membership is active;
 *  - `roles`, `permissions`: no scope. They are this client's own declared roles plus
 *    organization-wide ones, never another app's, and absent when the person holds none;
 *  - `organizations`: the `organizations` scope. Every active membership, across
 *    organizations, so it is behind a scope of its own. Present as an empty list when the
 *    person belongs to none: an absent claim would read as "not asked";
 *  - `feature_flags`: the `feature_flags` scope ({@see FeatureFlagClaim}).
 *
 * Everything is read when asked: the ID Token is a snapshot from the moment it was minted,
 * and UserInfo is live.
 */
class IdentityClaims
{
    public function __construct(
        private readonly Subjects $subjects,
        private readonly Organizations $organizations,
        private readonly Memberships $memberships,
        private readonly AccessChecker $access,
        private readonly FeatureFlagClaim $featureFlags,
    ) {}

    /**
     * @param  list<string>  $scopes  the GRANTED scopes
     * @param  string|null  $clientId  the client the answer is for; null leaves out roles and permissions
     * @return array<string, mixed>
     */
    public function for(string $subjectId, ?string $organizationId, ?string $clientId, array $scopes): array
    {
        $organizationId = $organizationId === '' ? null : $organizationId;

        return [
            ...$this->person($subjectId, $scopes),
            ...$this->organization($subjectId, $organizationId),
            ...$this->access($subjectId, $organizationId, $clientId),
            ...$this->memberships($subjectId, $scopes),
            ...$this->featureFlags($subjectId, $organizationId, $clientId, $scopes),
        ];
    }

    /**
     * @param  list<string>  $scopes
     * @return array<string, mixed>
     */
    private function person(string $subjectId, array $scopes): array
    {
        $email = in_array('email', $scopes, true);
        $profile = in_array('profile', $scopes, true);

        if (! $email && ! $profile) {
            return [];
        }

        $subject = $this->subjects->find($subjectId);

        if ($subject === null) {
            return [];
        }

        $claims = [];

        if ($email && $subject->email !== null) {
            $claims['email'] = $subject->email;
            // OIDC standard claim: lets a relying party refuse to trust the address
            // (for account linking, say) when it is not verified.
            $claims['email_verified'] = $subject->emailVerified;
        }

        if ($profile && $subject->name !== null) {
            $claims['name'] = $subject->name;
        }

        return $claims;
    }

    /**
     * The organization the grant is bound to: its id, the slug an app addresses it by, its
     * name, and the subject's current tier in it.
     *
     * @return array<string, mixed>
     */
    private function organization(string $subjectId, ?string $organizationId): array
    {
        if ($organizationId === null) {
            return [];
        }

        $claims = ['org' => $organizationId];
        $organization = $this->organizations->find($organizationId);

        if ($organization !== null) {
            if ($organization->slug !== '') {
                $claims['org_slug'] = $organization->slug;
            }

            if ($organization->name !== '') {
                $claims['org_name'] = $organization->name;
            }
        }

        // Absent when the membership is gone or not active.
        $tier = $this->memberships->activeRole($organizationId, $subjectId);

        if ($tier !== null) {
            $claims['org_role'] = $tier->value;
        }

        return $claims;
    }

    /**
     * Federated RBAC, as the access token carries it: the client's own declared roles plus
     * organization-wide ones. Without an organization, what the person holds
     * environment-wide.
     *
     * @return array<string, mixed>
     */
    private function access(string $subjectId, ?string $organizationId, ?string $clientId): array
    {
        if ($clientId === null) {
            return [];
        }

        $rbac = $this->access->forToken($subjectId, $organizationId, $clientId);

        return $rbac->isEmpty() ? [] : ['roles' => $rbac->roles, 'permissions' => $rbac->permissions];
    }

    /**
     * @param  list<string>  $scopes
     * @return array<string, mixed>
     */
    private function memberships(string $subjectId, array $scopes): array
    {
        if (! in_array('organizations', $scopes, true)) {
            return [];
        }

        $memberships = $this->memberships->forUser($subjectId)
            ->filter(fn (Membership $m): bool => $m->status === MembershipStatus::Active)
            ->values();

        if ($memberships->isEmpty()) {
            return ['organizations' => []];
        }

        // One query for every name and slug.
        $organizations = $this->organizations->findMany(
            $memberships->map(fn (Membership $m): string => $m->organization_id)->all()
        );

        return ['organizations' => $memberships
            ->map(fn (Membership $m): ?array => isset($organizations[$m->organization_id])
                ? [
                    'id' => $m->organization_id,
                    'name' => $organizations[$m->organization_id]->name,
                    'role' => $m->role->value,
                    'slug' => $organizations[$m->organization_id]->slug,
                ]
                : null)
            ->filter()
            ->values()
            ->all()];
    }

    /**
     * @param  list<string>  $scopes
     * @return array<string, mixed>
     */
    private function featureFlags(string $subjectId, ?string $organizationId, ?string $clientId, array $scopes): array
    {
        // A machine token's subject is its client: it has no user to evaluate for.
        $flags = $this->featureFlags->for($scopes, $clientId === $subjectId ? null : $subjectId, $organizationId);

        return $flags === null ? [] : [FeatureFlagClaim::CLAIM => $flags];
    }
}
