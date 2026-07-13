<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Organization\Contracts\OrganizationHierarchy;
use Cbox\Id\Organization\Exceptions\CannotReparent;
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

    public function move(string $organizationId, ?string $newParentId): void
    {
        // A node can't move beneath itself or its own descendant — that loops
        // the tree. (isDescendantOf is strict, so the self-check is explicit.)
        if ($newParentId !== null
            && ($newParentId === $organizationId || $this->isDescendantOf($newParentId, $organizationId))) {
            throw CannotReparent::intoOwnSubtree($organizationId, $newParentId);
        }

        // The subtree rooted at this node: (node, descendant, depth-within-subtree),
        // including the node's own depth-0 self-row. These internal links are kept.
        $subtree = OrganizationClosure::query()->where('ancestor_id', $organizationId)
            ->get(['descendant_id', 'depth']);
        $subtreeIds = $subtree->map(fn (OrganizationClosure $r): string => $r->descendant_id)->all();

        // Cut every link from an outside ancestor into the subtree; the internal
        // links (ancestor within the subtree) survive.
        OrganizationClosure::query()
            ->whereIn('descendant_id', $subtreeIds)
            ->whereNotIn('ancestor_id', $subtreeIds)
            ->delete();

        if ($newParentId === null) {
            return;
        }

        // Re-link: every ancestor of the new parent (including the parent itself)
        // becomes an ancestor of every node in the subtree, at the combined depth.
        $parentAncestry = OrganizationClosure::query()->where('descendant_id', $newParentId)
            ->get(['ancestor_id', 'depth']);

        foreach ($parentAncestry as $ancestor) {
            foreach ($subtree as $node) {
                OrganizationClosure::query()->create([
                    'ancestor_id' => $ancestor->ancestor_id,
                    'descendant_id' => $node->descendant_id,
                    'depth' => $ancestor->depth + 1 + $node->depth,
                ]);
            }
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
