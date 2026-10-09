<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

use InvalidArgumentException;

/**
 * An environment's authorization model: its resource types, the relations on each, and
 * how each relation is decided. What every fine-grained check is evaluated against.
 *
 * Built by {@see SchemaParser} from the schema language a person writes, and reloaded
 * from its JSON form ({@see self::fromArray()}) when a check runs — the stored form is the
 * parsed one, so a check never parses text.
 *
 * Besides the definitions it answers two questions the evaluator asks often enough to
 * keep: which relations a relation DEPENDS on (the validator walks it for cycles through
 * an exclusion, {@see self::dependencies()}), and the same graph reversed — "if a subject
 * has `viewer` on a folder, which relations on which types might that grant?" — which is
 * how a list-resources query walks outward from the subject ({@see self::grantedBy()}).
 */
final class AuthorizationSchema
{
    /** @var array<string, bool> type#relation => only union/computed/tuple-to-userset below it */
    private array $unionOnly = [];

    /** @var array<string, list<array{type: string, relation: string, via: 'computed'|'tupleset', tupleset: ?string}>>|null */
    private ?array $reverse = null;

    /** @var array<string, true>|null type#relation pairs some direct list names as a userset */
    private ?array $usersets = null;

    /**
     * @param  array<string, TypeDefinition>  $types  by name, in written order
     */
    public function __construct(public readonly array $types) {}

    public function type(string $name): ?TypeDefinition
    {
        return $this->types[$name] ?? null;
    }

    public function relation(string $type, string $relation): ?RelationDefinition
    {
        return ($this->types[$type] ?? null)?->relation($relation);
    }

    public function relationCount(): int
    {
        return array_sum(array_map(static fn (TypeDefinition $type): int => count($type->relations), $this->types));
    }

    /**
     * The relations (type#relation) $type#$relation is decided from, each marked when it
     * is reached through the subtracted side of an exclusion.
     *
     * @return list<array{type: string, relation: string, negative: bool}>
     */
    public function dependencies(string $type, string $relation): array
    {
        $definition = $this->relation($type, $relation);

        if ($definition === null) {
            return [];
        }

        $edges = [];
        $this->collect($type, $definition->rewrite, false, $edges);

        return $edges;
    }

    /**
     * Whether $type#$relation is decided by union alone, all the way down — no `and`, no
     * `but not` anywhere it depends on. For such a relation, walking the tuple graph as a
     * plain reachability question gives the exact answer, so list queries skip the
     * per-candidate check that set algebra needs.
     */
    public function isUnionOnly(string $type, string $relation): bool
    {
        $key = $type.'#'.$relation;

        if (isset($this->unionOnly[$key])) {
            return $this->unionOnly[$key];
        }

        $seen = [];
        $stack = [[$type, $relation]];
        $result = true;

        while ($stack !== []) {
            [$t, $r] = array_pop($stack);

            if (isset($seen[$t.'#'.$r])) {
                continue;
            }

            $seen[$t.'#'.$r] = true;
            $definition = $this->relation($t, $r);

            if ($definition === null) {
                continue;
            }

            if (self::usesSetAlgebra($definition->rewrite)) {
                $result = false;

                break;
            }

            foreach ($this->dependencies($t, $r) as $edge) {
                $stack[] = [$edge['type'], $edge['relation']];
            }
        }

        return $this->unionOnly[$key] = $result;
    }

    /**
     * The relations a subject holding $type#$relation on some object may thereby hold on
     * other objects — the dependency graph reversed, without the subtracted sides of
     * exclusions (which never ADD access).
     *
     *  - `computed`: the same object's `relation` (editor → viewer when `viewer: … or editor`);
     *  - `tupleset`: `relation` on every object of `type` whose `tupleset` tuples point at
     *    this one (folder viewer → document viewer when `viewer: … or viewer from parent`).
     *
     * Userset grants (`[group#member]`) are not listed: they are tuples naming the userset,
     * and the walk finds them by reading tuples, not the schema.
     *
     * @return list<array{type: string, relation: string, via: 'computed'|'tupleset', tupleset: ?string}>
     */
    public function grantedBy(string $type, string $relation): array
    {
        if ($this->reverse === null) {
            $this->reverse = [];

            foreach ($this->types as $owner) {
                foreach ($owner->relations as $definition) {
                    $this->reverseIndex($owner->name, $definition->name, $definition->rewrite);
                }
            }
        }

        return $this->reverse[$type.'#'.$relation] ?? [];
    }

    /**
     * Whether any relation's direct list names `$type#$relation` as a userset — i.e.
     * whether a tuple can name it at all. A list-resources walk asks this before it reads
     * the tuples naming a node: most nodes (a document's viewers) are never a userset, and
     * skipping the read for them is most of the walk's cost.
     */
    public function isUsersetTarget(string $type, string $relation): bool
    {
        if ($this->usersets === null) {
            $this->usersets = [];

            foreach ($this->types as $owner) {
                foreach ($owner->relations as $definition) {
                    foreach ($definition->directlyRelated()->types ?? [] as $direct) {
                        if ($direct->relation !== null) {
                            $this->usersets[$direct->type.'#'.$direct->relation] = true;
                        }
                    }
                }
            }
        }

        return isset($this->usersets[$type.'#'.$relation]);
    }

    /**
     * The JSON form, as stored and as an API answers.
     *
     * @return array{types: list<array{name: string, relations: list<array<string, mixed>>}>}
     */
    public function toArray(): array
    {
        return ['types' => array_values(array_map(static fn (TypeDefinition $type): array => $type->toArray(), $this->types))];
    }

    /**
     * The schema language, canonically: one type per paragraph, one relation per line.
     */
    public function toDsl(): string
    {
        $blocks = [];

        foreach ($this->types as $type) {
            $lines = ['type '.$type->name];

            foreach ($type->relations as $relation) {
                $lines[] = '  relation '.$relation->name.': '.$relation->rewrite->toDsl();
            }

            $blocks[] = implode("\n", $lines);
        }

        return implode("\n\n", $blocks)."\n";
    }

    /**
     * Rebuild a schema from {@see self::toArray()}. The input is the platform's own stored
     * form, so a malformed document is a bug, not a refusal.
     *
     * @param  array<mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $types = [];

        foreach (self::listOf($data['types'] ?? null) as $type) {
            $name = self::stringOf($type['name'] ?? null);
            $relations = [];

            foreach (self::listOf($type['relations'] ?? null) as $relation) {
                $relationName = self::stringOf($relation['name'] ?? null);
                $rewrite = $relation['rewrite'] ?? null;
                $relations[$relationName] = new RelationDefinition(
                    $relationName,
                    self::rewriteFrom(is_array($rewrite) ? $rewrite : []),
                );
            }

            $types[$name] = new TypeDefinition($name, $relations);
        }

        return new self($types);
    }

    /**
     * @param  array<mixed>  $node
     */
    private static function rewriteFrom(array $node): Rewrite
    {
        if (array_key_exists('direct', $node)) {
            return new DirectlyRelated(array_map(static function (array $type): DirectType {
                $relation = $type['relation'] ?? null;

                return new DirectType(self::stringOf($type['type'] ?? null), is_string($relation) ? $relation : null);
            }, self::listOf($node['direct'])));
        }

        if (array_key_exists('computed', $node)) {
            return new ComputedRelation(self::stringOf($node['computed']));
        }

        if (isset($node['from']) && is_array($node['from'])) {
            return new RelationFromTupleset(self::stringOf($node['from']['relation'] ?? null), self::stringOf($node['from']['tupleset'] ?? null));
        }

        if (array_key_exists('union', $node)) {
            return new UnionOf(array_map(self::rewriteFrom(...), self::listOf($node['union'])));
        }

        if (array_key_exists('intersection', $node)) {
            return new IntersectionOf(array_map(self::rewriteFrom(...), self::listOf($node['intersection'])));
        }

        if (isset($node['exclusion']) && is_array($node['exclusion'])) {
            $base = $node['exclusion']['base'] ?? null;
            $subtract = $node['exclusion']['subtract'] ?? null;

            return new ButNot(self::rewriteFrom(is_array($base) ? $base : []), self::rewriteFrom(is_array($subtract) ? $subtract : []));
        }

        throw new InvalidArgumentException('A stored authorization schema holds a rewrite of no known kind.');
    }

    /**
     * @return list<array<mixed>>
     */
    private static function listOf(mixed $value): array
    {
        if (! is_array($value)) {
            throw new InvalidArgumentException('A stored authorization schema is malformed: a list was expected.');
        }

        return array_values(array_filter($value, is_array(...)));
    }

    private static function stringOf(mixed $value): string
    {
        if (! is_string($value) || $value === '') {
            throw new InvalidArgumentException('A stored authorization schema is malformed: a name was expected.');
        }

        return $value;
    }

    private static function usesSetAlgebra(Rewrite $node): bool
    {
        if ($node instanceof IntersectionOf || $node instanceof ButNot) {
            return true;
        }

        foreach ($node->children() as $child) {
            if (self::usesSetAlgebra($child)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<array{type: string, relation: string, negative: bool}>  $edges
     */
    private function collect(string $type, Rewrite $node, bool $negative, array &$edges): void
    {
        if ($node instanceof DirectlyRelated) {
            foreach ($node->types as $direct) {
                if ($direct->relation !== null) {
                    $edges[] = ['type' => $direct->type, 'relation' => $direct->relation, 'negative' => $negative];
                }
            }

            return;
        }

        if ($node instanceof ComputedRelation) {
            $edges[] = ['type' => $type, 'relation' => $node->relation, 'negative' => $negative];

            return;
        }

        if ($node instanceof RelationFromTupleset) {
            $edges[] = ['type' => $type, 'relation' => $node->tupleset, 'negative' => $negative];

            foreach ($this->relation($type, $node->tupleset)?->directlyRelated()->types ?? [] as $target) {
                if ($this->relation($target->type, $node->relation) !== null) {
                    $edges[] = ['type' => $target->type, 'relation' => $node->relation, 'negative' => $negative];
                }
            }

            return;
        }

        if ($node instanceof ButNot) {
            $this->collect($type, $node->base, $negative, $edges);
            $this->collect($type, $node->subtract, true, $edges);

            return;
        }

        foreach ($node->children() as $child) {
            $this->collect($type, $child, $negative, $edges);
        }
    }

    private function reverseIndex(string $type, string $relation, Rewrite $node): void
    {
        if ($node instanceof ComputedRelation) {
            $this->reverse[$type.'#'.$node->relation][] = ['type' => $type, 'relation' => $relation, 'via' => 'computed', 'tupleset' => null];

            return;
        }

        if ($node instanceof RelationFromTupleset) {
            foreach ($this->relation($type, $node->tupleset)?->directlyRelated()->types ?? [] as $target) {
                $this->reverse[$target->type.'#'.$node->relation][] = ['type' => $type, 'relation' => $relation, 'via' => 'tupleset', 'tupleset' => $node->tupleset];
            }

            return;
        }

        if ($node instanceof ButNot) {
            $this->reverseIndex($type, $relation, $node->base);

            return;
        }

        foreach ($node->children() as $child) {
            $this->reverseIndex($type, $relation, $child);
        }
    }
}
