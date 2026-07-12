<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization;

use Cbox\Id\Kernel\Authorization\Contracts\RelationshipStore;
use Cbox\Id\Kernel\Authorization\Models\RelationshipTuple;
use Cbox\Id\Kernel\Authorization\ValueObjects\Relationship;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\GenericTenant;

/**
 * Right-sized ReBAC over Postgres: direct tuples plus bounded, recursive
 * userset expansion. Traversal carries a visited set, so each userset node is
 * expanded at most once — a crafted dense/cyclic graph resolves in O(V+E)
 * rather than exploding combinatorially (the depth cap is a secondary guard).
 */
final class DatabaseRelationshipStore implements RelationshipStore
{
    private const MAX_DEPTH = 12;

    public function __construct(private readonly TenantContext $tenant) {}

    public function write(Relationship $relationship): void
    {
        $this->tenant->runAs(
            GenericTenant::of($relationship->organizationId),
            fn () => RelationshipTuple::query()->updateOrCreate($this->identity($relationship)),
        );
    }

    public function delete(Relationship $relationship): void
    {
        $this->tenant->runAs(
            GenericTenant::of($relationship->organizationId),
            fn () => RelationshipTuple::query()->where($this->identity($relationship))->delete(),
        );
    }

    public function check(
        string $organizationId,
        string $objectType,
        string $objectId,
        string $relation,
        string $subjectType,
        string $subjectId,
    ): bool {
        // Run the whole traversal inside the tenant scope: the tuple models are
        // tenant-owned, so every query is confined to this org (defense-in-depth
        // beyond the explicit organization_id filters below).
        return $this->tenant->runAs(GenericTenant::of($organizationId), function () use ($organizationId, $objectType, $objectId, $relation, $subjectType, $subjectId): bool {
            $visited = [];

            return $this->checkAtDepth($organizationId, $objectType, $objectId, $relation, $subjectType, $subjectId, 0, $visited);
        });
    }

    /**
     * @param  array<string, true>  $visited  userset nodes already expanded
     */
    private function checkAtDepth(
        string $organizationId,
        string $objectType,
        string $objectId,
        string $relation,
        string $subjectType,
        string $subjectId,
        int $depth,
        array &$visited,
    ): bool {
        if ($depth >= self::MAX_DEPTH) {
            return false;
        }

        // A userset node is fully determined by (object, relation) for a fixed
        // subject — expanding it twice can only repeat the same answer.
        $node = $objectType.'|'.$objectId.'|'.$relation;

        if (isset($visited[$node])) {
            return false;
        }

        $visited[$node] = true;

        $directGrant = RelationshipTuple::query()
            ->where('organization_id', $organizationId)
            ->where('object_type', $objectType)
            ->where('object_id', $objectId)
            ->where('relation', $relation)
            ->where('subject_type', $subjectType)
            ->where('subject_id', $subjectId)
            ->whereNull('subject_relation')
            ->exists();

        if ($directGrant) {
            return true;
        }

        $usersets = RelationshipTuple::query()
            ->where('organization_id', $organizationId)
            ->where('object_type', $objectType)
            ->where('object_id', $objectId)
            ->where('relation', $relation)
            ->whereNotNull('subject_relation')
            ->get();

        foreach ($usersets as $tuple) {
            $viaRelation = $tuple->subject_relation;

            if ($viaRelation === null) {
                continue;
            }

            $granted = $this->checkAtDepth(
                $organizationId,
                $tuple->subject_type,
                $tuple->subject_id,
                $viaRelation,
                $subjectType,
                $subjectId,
                $depth + 1,
                $visited,
            );

            if ($granted) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, string|null>
     */
    private function identity(Relationship $relationship): array
    {
        return [
            'organization_id' => $relationship->organizationId,
            'object_type' => $relationship->objectType,
            'object_id' => $relationship->objectId,
            'relation' => $relationship->relation,
            'subject_type' => $relationship->subjectType,
            'subject_id' => $relationship->subjectId,
            'subject_relation' => $relationship->subjectRelation,
        ];
    }
}
