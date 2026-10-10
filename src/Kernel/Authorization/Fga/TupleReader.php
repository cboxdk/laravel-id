<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Fga;

use Cbox\Id\Kernel\Authorization\ValueObjects\SubjectRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Tuple;

/**
 * The four questions {@see Evaluator} asks of an environment's stored tuples — and
 * nothing else, so the evaluator runs the same over the database
 * ({@see DatabaseTupleReader}) and over a plain array ({@see InMemoryTupleReader}),
 * which is how it is tested against a reference implementation on random graphs.
 */
interface TupleReader
{
    /** Is exactly `$type:$id#$relation@$subject` stored? */
    public function has(string $type, string $id, string $relation, SubjectRef $subject): bool;

    /**
     * In one read: whether $subject itself is named on `$type:$id#$relation`, and the
     * usersets named there — the two things a direct list is decided from.
     *
     * @return array{0: bool, 1: list<SubjectRef>}
     */
    public function direct(string $type, string $id, string $relation, SubjectRef $subject): array;

    /**
     * The usersets (`group:eng#member`) named on `$type:$id#$relation`.
     *
     * @return list<SubjectRef>
     */
    public function usersets(string $type, string $id, string $relation): array;

    /**
     * Every subject named on `$type:$id#$relation`, direct and userset.
     *
     * @return list<SubjectRef>
     */
    public function subjects(string $type, string $id, string $relation): array;

    /**
     * The tuples that name exactly $subject, optionally only on one resource type and
     * relation — the reverse direction, for list-resources.
     *
     * @return list<Tuple>
     */
    public function naming(SubjectRef $subject, ?string $resourceType = null, ?string $relation = null): array;
}
