<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\ValueObjects;

use Cbox\Id\Organization\Enums\MembershipRole;

/**
 * An RBAC decision for one subject, one organization (or none) and one app.
 *
 * `organizationActive` is false when the organization exists and its status revokes
 * access (suspended, archived): every check is then denied, whatever the subject holds,
 * because a suspended organization's members are refused everywhere else too.
 */
readonly class PermissionDecision
{
    /**
     * @param  list<PermissionCheck>  $checks
     */
    public function __construct(
        public string $userId,
        public ?string $organizationId,
        public string $clientId,
        public ?MembershipRole $organizationRole,
        public bool $organizationActive,
        public array $checks,
    ) {}

    /** True only when every requested permission is held — and at least one was asked. */
    public function allowed(): bool
    {
        if ($this->checks === []) {
            return false;
        }

        foreach ($this->checks as $check) {
            if (! $check->allowed) {
                return false;
            }
        }

        return true;
    }

    /**
     * The `POST /oauth/decisions` RBAC response body.
     *
     * @return array{mode: string, subject: array{type: string, id: string}, organization: string|null, client_id: string, org_role: string|null, organization_active: bool, allowed: bool, results: list<array{permission: string, allowed: bool}>}
     */
    public function toArray(): array
    {
        return [
            'mode' => 'rbac',
            'subject' => ['type' => 'user', 'id' => $this->userId],
            'organization' => $this->organizationId,
            'client_id' => $this->clientId,
            'org_role' => $this->organizationRole?->value,
            'organization_active' => $this->organizationActive,
            'allowed' => $this->allowed(),
            'results' => array_map(
                static fn (PermissionCheck $check): array => ['permission' => $check->permission, 'allowed' => $check->allowed],
                $this->checks,
            ),
        ];
    }
}
