<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Organization\Contracts\OrganizationHierarchy;
use Cbox\Id\Organization\Models\OrganizationClosure;

final class ClosureOrganizationHierarchy implements OrganizationHierarchy
{
    public function attach(string $organizationId, ?string $parentId): void
    {
        OrganizationClosure::query()->create([
            'ancestor_id' => $organizationId,
            'descendant_id' => $organizationId,
            'depth' => 0,
        ]);

        if ($parentId === null) {
            return;
        }

        // Every ancestor of the parent (including the parent itself) becomes an
        // ancestor of this node, one level deeper.
        $parentAncestry = OrganizationClosure::query()->where('descendant_id', $parentId)->get();

        foreach ($parentAncestry as $row) {
            OrganizationClosure::query()->create([
                'ancestor_id' => $row->ancestor_id,
                'descendant_id' => $organizationId,
                'depth' => $row->depth + 1,
            ]);
        }
    }

    public function descendants(string $organizationId): array
    {
        return array_values(
            OrganizationClosure::query()
                ->where('ancestor_id', $organizationId)
                ->where('depth', '>', 0)
                ->get()
                ->map(fn (OrganizationClosure $row): string => $row->descendant_id)
                ->all()
        );
    }

    public function ancestors(string $organizationId): array
    {
        return array_values(
            OrganizationClosure::query()
                ->where('descendant_id', $organizationId)
                ->where('depth', '>', 0)
                ->get()
                ->map(fn (OrganizationClosure $row): string => $row->ancestor_id)
                ->all()
        );
    }

    public function isDescendantOf(string $organizationId, string $ancestorId): bool
    {
        return OrganizationClosure::query()
            ->where('ancestor_id', $ancestorId)
            ->where('descendant_id', $organizationId)
            ->where('depth', '>', 0)
            ->exists();
    }

    public function manages(string $managerId, string $organizationId): bool
    {
        return $managerId === $organizationId
            || $this->isDescendantOf($organizationId, $managerId);
    }
}
