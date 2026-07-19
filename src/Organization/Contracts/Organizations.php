<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Organization\ValueObjects\NewOrganization;

interface Organizations
{
    public function create(NewOrganization $input): Organization;

    /**
     * Merge and persist organization settings (branding, preferences, …).
     *
     * @param  array<string, mixed>  $settings
     */
    public function updateSettings(string $id, array $settings): Organization;

    public function find(string $id): ?Organization;

    /**
     * Batch-load organizations by id, keyed by id — the N+1-free counterpart to
     * {@see find} (e.g. resolving names for a membership list / org switcher).
     * Missing ids are simply absent from the result.
     *
     * @param  array<int, string>  $ids
     * @return array<string, Organization>
     */
    public function findMany(array $ids): array;

    public function bySlug(string $slug): ?Organization;

    /**
     * Suspend an organization: set its status to Suspended and record the change
     * on the tenant's audit trail. A suspended org's members are refused by the
     * host's request pipeline (deny-by-default). `$actorId` attributes the action
     * to the operator who performed it.
     */
    public function suspend(string $id, string $actorId): Organization;

    /**
     * Lift a suspension, returning the organization to Active.
     */
    public function reactivate(string $id, string $actorId): Organization;
}
