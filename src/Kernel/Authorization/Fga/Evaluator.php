<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Fga;

use Cbox\Id\Kernel\Authorization\Exceptions\ResolutionTooComplex;
use Cbox\Id\Kernel\Authorization\Schema\AuthorizationSchema;
use Cbox\Id\Kernel\Authorization\Schema\ButNot;
use Cbox\Id\Kernel\Authorization\Schema\ComputedRelation;
use Cbox\Id\Kernel\Authorization\Schema\DirectlyRelated;
use Cbox\Id\Kernel\Authorization\Schema\IntersectionOf;
use Cbox\Id\Kernel\Authorization\Schema\RelationFromTupleset;
use Cbox\Id\Kernel\Authorization\Schema\Rewrite;
use Cbox\Id\Kernel\Authorization\Schema\SchemaValidator;
use Cbox\Id\Kernel\Authorization\Schema\UnionOf;
use Cbox\Id\Kernel\Authorization\ValueObjects\SubjectRef;
use Closure;

/**
 * THE EVALUATOR — answers checks and list queries for one schema over one set of tuples.
 *
 * A relation's meaning is the LEAST FIXPOINT of its definition: a subject has it exactly
 * when there is a finite chain of tuples and rewrites that derives it. Cycles are normal
 * (groups inside groups, folders inside folders) and contribute nothing on their own.
 *
 * CHECK is a depth-first search for such a derivation:
 *
 *  - an (object, relation) node already on the current path is a cycle, and answers "no"
 *    on this path — a shortest derivation never visits a node twice, so this loses no
 *    real grant (that is what makes the ROOT's answer exact);
 *  - a node's answer is remembered for the rest of the call when it is "yes", or when it
 *    is "no" and its search never ran into such a cycle; a "no" that leaned on a cut is
 *    only true for that path and is recomputed if asked again. The memo is what keeps a
 *    dense or cyclic graph polynomial — each node is fully expanded at most once per
 *    subject;
 *  - `but not` evaluates its subtracted side in a fresh frame and needs the exact answer
 *    there: the schema guarantees that side never depends on the relation being decided
 *    ({@see SchemaValidator}), so a fresh frame
 *    gives one;
 *  - depth is bounded (`max_depth`). Past it the check REFUSES rather than answering —
 *    "no" would be wrong for a grant further down, and wrong the other way inside a
 *    `but not`.
 *
 * LIST queries walk the tuple graph as if every operator were a union (the subtracted
 * side of `but not` dropped): a superset of the answer, bounded by `max_expansion`
 * visited nodes. Where the relation is union-only all the way down that superset IS the
 * answer; otherwise each candidate is confirmed with a check. list-resources walks
 * outward from the subject using the schema's reverse edges; list-subjects walks inward
 * from the resource.
 *
 * One instance per call (or per batch): its memo is only valid for one revision.
 */
final class Evaluator
{
    /** @var array<string, array<string, bool>> subject => node => answer */
    private array $memo = [];

    /** @var array<string, true> the nodes on the current search path */
    private array $path = [];

    /** Whether the current subtree's search ran into a node on the path. */
    private bool $cut = false;

    public function __construct(
        private readonly AuthorizationSchema $schema,
        private readonly TupleReader $tuples,
        private readonly int $maxDepth = 25,
        private readonly int $maxExpansion = 50_000,
    ) {}

    /**
     * Does $subject have $relation on $type:$id?
     *
     * @throws ResolutionTooComplex
     */
    public function check(string $type, string $id, string $relation, SubjectRef $subject): bool
    {
        $this->path = [];
        $this->cut = false;

        return $this->node($type, $id, $relation, $subject, 0);
    }

    /**
     * The ids of the $resourceType objects $subject has $relation on, sorted, after
     * $after, at most $limit — and whether there are more.
     *
     * @return array{ids: list<string>, more: bool}
     *
     * @throws ResolutionTooComplex
     */
    public function resources(SubjectRef $subject, string $relation, string $resourceType, int $limit, ?string $after = null): array
    {
        $found = [];
        $visited = [];
        $queue = [];

        if ($subject->relation !== null) {
            $queue[] = [$subject->type, $subject->id, $subject->relation];
        }

        foreach ($this->tuples->naming($subject) as $tuple) {
            $queue[] = [$tuple->resource->type, $tuple->resource->id, $tuple->relation];
        }

        while ($queue !== []) {
            [$type, $id, $rel] = array_pop($queue);
            $key = $type.':'.$id.'#'.$rel;

            if (isset($visited[$key])) {
                continue;
            }

            $this->visit($visited, $key);

            if ($type === $resourceType && $rel === $relation) {
                $found[$id] = true;
            }

            // A userset: tuples naming "everybody with $rel on $type:$id" — read only where
            // the schema lets a tuple name one.
            if ($this->schema->isUsersetTarget($type, $rel)) {
                foreach ($this->tuples->naming(SubjectRef::of($type, $id, $rel)) as $tuple) {
                    $queue[] = [$tuple->resource->type, $tuple->resource->id, $tuple->relation];
                }
            }

            foreach ($this->schema->grantedBy($type, $rel) as $edge) {
                if ($edge['via'] === 'computed') {
                    $queue[] = [$type, $id, $edge['relation']];

                    continue;
                }

                // $type:$id is the target of some `tupleset` tuple on an $edge['type'].
                foreach ($this->tuples->naming(SubjectRef::of($type, $id), $edge['type'], (string) $edge['tupleset']) as $tuple) {
                    $queue[] = [$edge['type'], $tuple->resource->id, $edge['relation']];
                }
            }
        }

        return $this->page(
            array_map(strval(...), array_keys($found)),
            $this->schema->isUnionOnly($resourceType, $relation)
                ? null
                : fn (string $id): bool => $this->check($resourceType, $id, $relation, $subject),
            $limit,
            $after,
        );
    }

    /**
     * The ids of the $subjectType subjects that have $relation on $type:$id — direct
     * subjects only, every userset expanded — sorted, paged as {@see self::resources()}.
     *
     * @return array{ids: list<string>, more: bool}
     *
     * @throws ResolutionTooComplex
     */
    public function subjects(string $type, string $id, string $relation, string $subjectType, int $limit, ?string $after = null): array
    {
        $found = [];
        $visited = [];
        $queue = [[$type, $id, $relation]];

        while ($queue !== []) {
            [$t, $i, $r] = array_pop($queue);
            $key = $t.':'.$i.'#'.$r;

            if (isset($visited[$key])) {
                continue;
            }

            $this->visit($visited, $key);
            $definition = $this->schema->relation($t, $r);

            if ($definition !== null) {
                $this->expand($t, $i, $r, $definition->rewrite, $subjectType, $found, $queue);
            }
        }

        return $this->page(
            array_map(strval(...), array_keys($found)),
            $this->schema->isUnionOnly($type, $relation)
                ? null
                : fn (string $candidate): bool => $this->check($type, $id, $relation, SubjectRef::of($subjectType, $candidate)),
            $limit,
            $after,
        );
    }

    /**
     * @phpstan-impure
     *
     * @throws ResolutionTooComplex
     */
    private function node(string $type, string $id, string $relation, SubjectRef $subject, int $depth): bool
    {
        // A userset contains itself: "members of group eng" are members of group eng.
        if ($subject->relation === $relation && $subject->id === $id && $subject->type === $type) {
            return true;
        }

        $definition = $this->schema->relation($type, $relation);

        if ($definition === null) {
            return false;
        }

        $who = (string) $subject;
        $key = $type.':'.$id.'#'.$relation;

        if (isset($this->memo[$who][$key])) {
            return $this->memo[$who][$key];
        }

        if (isset($this->path[$key])) {
            $this->cut = true;

            return false;
        }

        if ($depth >= $this->maxDepth) {
            throw ResolutionTooComplex::depth($this->maxDepth);
        }

        $this->path[$key] = true;
        $outer = $this->cut;
        $this->cut = false;

        try {
            $answer = $this->rewrite($type, $id, $relation, $definition->rewrite, $subject, $depth);
        } finally {
            unset($this->path[$key]);
        }

        if ($answer || ! $this->cut) {
            $this->memo[$who][$key] = $answer;
        }

        $this->cut = $outer || $this->cut;

        return $answer;
    }

    /**
     * Impure: it marks the path and the cut flag as it searches.
     *
     * @phpstan-impure
     *
     * @throws ResolutionTooComplex
     */
    private function rewrite(string $type, string $id, string $relation, Rewrite $node, SubjectRef $subject, int $depth): bool
    {
        if ($node instanceof DirectlyRelated) {
            [$named, $usersets] = $this->tuples->direct($type, $id, $relation, $subject);

            if ($named && $node->allows($subject->type, $subject->relation)) {
                return true;
            }

            foreach ($usersets as $userset) {
                if ($node->allows($userset->type, $userset->relation)
                    && $this->node($userset->type, $userset->id, (string) $userset->relation, $subject, $depth + 1)) {
                    return true;
                }
            }

            return false;
        }

        if ($node instanceof ComputedRelation) {
            return $this->node($type, $id, $node->relation, $subject, $depth + 1);
        }

        if ($node instanceof RelationFromTupleset) {
            foreach ($this->tuples->subjects($type, $id, $node->tupleset) as $object) {
                if ($object->relation === null
                    && $this->schema->relation($object->type, $node->relation) !== null
                    && $this->node($object->type, $object->id, $node->relation, $subject, $depth + 1)) {
                    return true;
                }
            }

            return false;
        }

        if ($node instanceof UnionOf) {
            foreach ($node->operands as $operand) {
                if ($this->rewrite($type, $id, $relation, $operand, $subject, $depth)) {
                    return true;
                }
            }

            return false;
        }

        if ($node instanceof IntersectionOf) {
            foreach ($node->operands as $operand) {
                if (! $this->rewrite($type, $id, $relation, $operand, $subject, $depth)) {
                    return false;
                }
            }

            return true;
        }

        if ($node instanceof ButNot) {
            if (! $this->rewrite($type, $id, $relation, $node->base, $subject, $depth)) {
                return false;
            }

            return ! $this->isolated(fn (): bool => $this->rewrite($type, $id, $relation, $node->subtract, $subject, $depth));
        }

        return false;
    }

    /**
     * Run $evaluate with an empty path, as its own search: the exact answer an exclusion
     * needs for its subtracted side. The outer path and cut flag are put back afterwards.
     *
     * @param  Closure(): bool  $evaluate
     */
    private function isolated(Closure $evaluate): bool
    {
        $path = $this->path;
        $cut = $this->cut;
        $this->path = [];
        $this->cut = false;

        try {
            return $evaluate();
        } finally {
            $this->path = $path;
            $this->cut = $cut;
        }
    }

    /**
     * One inward step of list-subjects: what $t:$i#$r's definition points at, every
     * operator read as a union and the subtracted side of `but not` dropped.
     *
     * @param  array<string, true>  $found
     * @param  list<array{0: string, 1: string, 2: string}>  $queue
     */
    private function expand(string $t, string $i, string $r, Rewrite $node, string $subjectType, array &$found, array &$queue): void
    {
        if ($node instanceof DirectlyRelated) {
            foreach ($this->tuples->subjects($t, $i, $r) as $subject) {
                if (! $node->allows($subject->type, $subject->relation)) {
                    continue;
                }

                if ($subject->relation !== null) {
                    $queue[] = [$subject->type, $subject->id, $subject->relation];
                } elseif ($subject->type === $subjectType) {
                    $found[$subject->id] = true;
                }
            }

            return;
        }

        if ($node instanceof ComputedRelation) {
            $queue[] = [$t, $i, $node->relation];

            return;
        }

        if ($node instanceof RelationFromTupleset) {
            foreach ($this->tuples->subjects($t, $i, $node->tupleset) as $object) {
                if ($object->relation === null && $this->schema->relation($object->type, $node->relation) !== null) {
                    $queue[] = [$object->type, $object->id, $node->relation];
                }
            }

            return;
        }

        if ($node instanceof ButNot) {
            $this->expand($t, $i, $r, $node->base, $subjectType, $found, $queue);

            return;
        }

        foreach ($node->children() as $child) {
            $this->expand($t, $i, $r, $child, $subjectType, $found, $queue);
        }
    }

    /**
     * @param  array<string, true>  $visited
     *
     * @throws ResolutionTooComplex
     */
    private function visit(array &$visited, string $key): void
    {
        $visited[$key] = true;

        if (count($visited) > $this->maxExpansion) {
            throw ResolutionTooComplex::breadth($this->maxExpansion);
        }
    }

    /**
     * Sort the candidates, skip to after the cursor, and confirm each with $confirm (when
     * the walk was only a superset) until a page and one more are found.
     *
     * @param  list<string>  $candidates
     * @param  (Closure(string): bool)|null  $confirm
     * @return array{ids: list<string>, more: bool}
     */
    private function page(array $candidates, ?Closure $confirm, int $limit, ?string $after): array
    {
        sort($candidates, SORT_STRING);
        $ids = [];

        foreach ($candidates as $candidate) {
            if ($after !== null && strcmp($candidate, $after) <= 0) {
                continue;
            }

            if ($confirm !== null && ! $confirm($candidate)) {
                continue;
            }

            if (count($ids) === $limit) {
                return ['ids' => $ids, 'more' => true];
            }

            $ids[] = $candidate;
        }

        return ['ids' => $ids, 'more' => false];
    }
}
