<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization;

use Cbox\Id\Kernel\Authorization\Contracts\RelationshipStore;
use Cbox\Id\Kernel\Authorization\Models\RelationshipTuple;
use Cbox\Id\Kernel\Authorization\ValueObjects\Relationship;

/**
 * Right-sized ReBAC over Postgres: direct tuples plus bounded, recursive
 * userset expansion. The depth cap makes cyclic data safe (it terminates and
 * denies) without needing Zanzibar's zookies.
 */
final class DatabaseRelationshipStore implements RelationshipStore
{
    private const MAX_DEPTH = 12;

    public function write(Relationship $relationship): void
    {
        RelationshipTuple::query()->updateOrCreate($this->identity($relationship));
    }

    public function delete(Relationship $relationship): void
    {
        RelationshipTuple::query()->where($this->identity($relationship))->delete();
    }

    public function check(
        string $organizationId,
        string $objectType,
        string $objectId,
        string $relation,
        string $subjectType,
        string $subjectId,
    ): bool {
        return $this->checkAtDepth($organizationId, $objectType, $objectId, $relation, $subjectType, $subjectId, 0);
    }

    private function checkAtDepth(
        string $organizationId,
        string $objectType,
        string $objectId,
        string $relation,
        string $subjectType,
        string $subjectId,
        int $depth,
    ): bool {
        if ($depth >= self::MAX_DEPTH) {
            return false;
        }

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
