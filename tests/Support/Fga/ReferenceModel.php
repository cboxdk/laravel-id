<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Support\Fga;

use Cbox\Id\Kernel\Authorization\Schema\AuthorizationSchema;
use Cbox\Id\Kernel\Authorization\Schema\ButNot;
use Cbox\Id\Kernel\Authorization\Schema\ComputedRelation;
use Cbox\Id\Kernel\Authorization\Schema\DirectlyRelated;
use Cbox\Id\Kernel\Authorization\Schema\IntersectionOf;
use Cbox\Id\Kernel\Authorization\Schema\RelationFromTupleset;
use Cbox\Id\Kernel\Authorization\Schema\Rewrite;
use Cbox\Id\Kernel\Authorization\Schema\UnionOf;
use Cbox\Id\Kernel\Authorization\ValueObjects\Tuple;
use LogicException;

/**
 * THE REFERENCE IMPLEMENTATION the evaluator is tested against: the meaning of a schema,
 * computed the slow, obvious way.
 *
 * Every (object, relation) of a small universe gets the set of users that have it,
 * computed bottom-up as a least fixpoint — start from nothing and re-apply every
 * definition until nothing changes. Exclusions make that non-monotone, so relations are
 * first put in STRATA (a relation sits above everything it subtracts) and each stratum is
 * iterated to its fixpoint before the next one starts. No search, no memo, no cycle
 * handling: cycles simply converge.
 *
 * It shares nothing with the evaluator but the parsed schema, so agreement on random
 * graphs means the evaluator's search, memo and cut-off rules compute the same thing.
 */
final class ReferenceModel
{
    /** @var array<string, array<string, true>> object#relation => user id => true */
    private array $sets = [];

    /**
     * @param  array<string, list<string>>  $ids  type => the ids of its objects in this universe
     * @param  list<Tuple>  $tuples
     */
    public function __construct(
        private readonly AuthorizationSchema $schema,
        private readonly array $ids,
        private readonly array $tuples,
    ) {
        $this->compute();
    }

    public function allows(string $type, string $id, string $relation, string $user): bool
    {
        return isset($this->sets[$type.':'.$id.'#'.$relation][$user]);
    }

    /**
     * @return list<string>
     */
    public function users(string $type, string $id, string $relation): array
    {
        $users = array_map(strval(...), array_keys($this->sets[$type.':'.$id.'#'.$relation] ?? []));
        sort($users, SORT_STRING);

        return $users;
    }

    /**
     * @return list<string>
     */
    public function resources(string $user, string $relation, string $type): array
    {
        $found = [];

        foreach ($this->ids[$type] ?? [] as $id) {
            if ($this->allows($type, $id, $relation, $user)) {
                $found[] = $id;
            }
        }

        sort($found, SORT_STRING);

        return $found;
    }

    private function compute(): void
    {
        $strata = $this->strata();
        $levels = $strata === [] ? [] : range(0, max($strata));

        foreach ($levels as $level) {
            do {
                $changed = false;

                foreach ($this->schema->types as $type) {
                    foreach ($type->relations as $relation) {
                        if ($strata[$type->name.'#'.$relation->name] !== $level) {
                            continue;
                        }

                        foreach ($this->ids[$type->name] ?? [] as $id) {
                            $key = $type->name.':'.$id.'#'.$relation->name;
                            $next = $this->evaluate($type->name, $id, $relation->name, $relation->rewrite);

                            if ($next != ($this->sets[$key] ?? [])) {
                                $this->sets[$key] = $next;
                                $changed = true;
                            }
                        }
                    }
                }
            } while ($changed);
        }
    }

    /**
     * @return array<string, true>
     */
    private function evaluate(string $type, string $id, string $relation, Rewrite $node): array
    {
        if ($node instanceof DirectlyRelated) {
            $users = [];

            foreach ($this->tuples as $tuple) {
                if ($tuple->resource->type !== $type || $tuple->resource->id !== $id || $tuple->relation !== $relation) {
                    continue;
                }

                $subject = $tuple->subject;

                if ($subject->relation === null && $subject->type === 'user') {
                    $users[$subject->id] = true;
                } elseif ($subject->relation !== null) {
                    $users += $this->sets[$subject->type.':'.$subject->id.'#'.$subject->relation] ?? [];
                }
            }

            return $users;
        }

        if ($node instanceof ComputedRelation) {
            return $this->sets[$type.':'.$id.'#'.$node->relation] ?? [];
        }

        if ($node instanceof RelationFromTupleset) {
            $users = [];

            foreach ($this->tuples as $tuple) {
                if ($tuple->resource->type === $type && $tuple->resource->id === $id && $tuple->relation === $node->tupleset && $tuple->subject->relation === null) {
                    $users += $this->sets[$tuple->subject->type.':'.$tuple->subject->id.'#'.$node->relation] ?? [];
                }
            }

            return $users;
        }

        if ($node instanceof UnionOf) {
            $users = [];

            foreach ($node->operands as $operand) {
                $users += $this->evaluate($type, $id, $relation, $operand);
            }

            return $users;
        }

        if ($node instanceof IntersectionOf) {
            $users = null;

            foreach ($node->operands as $operand) {
                $next = $this->evaluate($type, $id, $relation, $operand);
                $users = $users === null ? $next : array_intersect_key($users, $next);
            }

            return $users ?? [];
        }

        if ($node instanceof ButNot) {
            return array_diff_key(
                $this->evaluate($type, $id, $relation, $node->base),
                $this->evaluate($type, $id, $relation, $node->subtract),
            );
        }

        throw new LogicException('Unknown rewrite.');
    }

    /**
     * A stratum per relation: at least that of everything it depends on, and one above
     * everything it subtracts.
     *
     * @return array<string, int>
     */
    private function strata(): array
    {
        $strata = [];

        foreach ($this->schema->types as $type) {
            foreach ($type->relations as $relation) {
                $strata[$type->name.'#'.$relation->name] = 0;
            }
        }

        do {
            $changed = false;

            foreach ($this->schema->types as $type) {
                foreach ($type->relations as $relation) {
                    $self = $type->name.'#'.$relation->name;

                    foreach ($this->schema->dependencies($type->name, $relation->name) as $edge) {
                        $needed = ($strata[$edge['type'].'#'.$edge['relation']] ?? 0) + ($edge['negative'] ? 1 : 0);

                        if ($needed > $strata[$self]) {
                            $strata[$self] = $needed;
                            $changed = true;
                        }
                    }
                }
            }
        } while ($changed);

        return $strata;
    }
}
