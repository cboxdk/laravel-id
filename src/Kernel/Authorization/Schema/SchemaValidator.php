<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

/**
 * Whether a parsed schema means something: every name it uses is one it defines, every
 * inheritance points at a relation that exists, and no relation subtracts itself.
 *
 * WHAT IS REFUSED, and why each would otherwise be a silent wrong answer:
 *
 *  - an unknown type or relation, anywhere — a check against it could only ever say no,
 *    and a typo would deny everybody without a word;
 *  - `viewer from parent` where `parent` is not a plain list of object types (`[folder]`):
 *    the evaluator follows those tuples to OBJECTS, and a userset or a computed tupleset
 *    has none to follow; and where no type `parent` points at has a `viewer` at all;
 *  - more than one `[...]` list on one relation — a tuple is written against THE list;
 *  - a cycle through `but not`: "a viewer, but not a viewer" has no answer. Cycles that
 *    only ever ADD access are allowed — nested groups and folder trees are cycles in the
 *    schema — and are bounded at evaluation time instead;
 *  - names that are not short lower-case words: they are stored in tuple columns 64
 *    characters wide, and `:`, `#` and `@` are the tuple notation's own separators.
 */
final class SchemaValidator
{
    public const int MAX_TYPES = 200;

    public const int MAX_RELATIONS_PER_TYPE = 100;

    /** Lower-case, starting with a letter, at most 64 characters. */
    public const string NAME_PATTERN = '/^[a-z][a-z0-9_-]{0,63}$/';

    /**
     * @return list<SchemaError>
     */
    public function validate(AuthorizationSchema $schema): array
    {
        $errors = [];

        if (count($schema->types) > self::MAX_TYPES) {
            $errors[] = new SchemaError(0, 'A schema may define at most '.self::MAX_TYPES.' types.');
        }

        foreach ($schema->types as $type) {
            if (preg_match(self::NAME_PATTERN, $type->name) !== 1) {
                $errors[] = new SchemaError($type->line, "`{$type->name}` is not a valid type name: use lower-case letters, digits, `_` and `-`, starting with a letter.");
            }

            if (count($type->relations) > self::MAX_RELATIONS_PER_TYPE) {
                $errors[] = new SchemaError($type->line, "`{$type->name}` defines more than ".self::MAX_RELATIONS_PER_TYPE.' relations.');
            }

            foreach ($type->relations as $relation) {
                if (preg_match(self::NAME_PATTERN, $relation->name) !== 1) {
                    $errors[] = new SchemaError($relation->line, "`{$relation->name}` is not a valid relation name: use lower-case letters, digits, `_` and `-`, starting with a letter.");
                }

                $errors = [...$errors, ...$this->relation($schema, $type, $relation)];
            }
        }

        return [...$errors, ...$this->negativeCycles($schema)];
    }

    /**
     * @return list<SchemaError>
     */
    private function relation(AuthorizationSchema $schema, TypeDefinition $type, RelationDefinition $relation): array
    {
        $errors = [];
        $lists = 0;
        $where = "`{$relation->name}` on `{$type->name}`";

        $this->walk($relation->rewrite, function (Rewrite $node) use ($schema, $type, $relation, $where, &$errors, &$lists): void {
            if ($node instanceof DirectlyRelated) {
                $lists++;
                $seen = [];

                foreach ($node->types as $direct) {
                    $label = $direct->toDsl();

                    if (isset($seen[$label])) {
                        $errors[] = new SchemaError($relation->line, "{$where} lists `{$label}` twice.");
                    }

                    $seen[$label] = true;

                    if ($schema->type($direct->type) === null) {
                        $errors[] = new SchemaError($relation->line, "{$where} names the type `{$direct->type}`, which is not defined.");
                    } elseif ($direct->relation !== null && $schema->relation($direct->type, $direct->relation) === null) {
                        $errors[] = new SchemaError($relation->line, "{$where} names `{$label}`, but `{$direct->type}` has no relation `{$direct->relation}`.");
                    }
                }

                return;
            }

            if ($node instanceof ComputedRelation) {
                if ($node->relation === $relation->name) {
                    $errors[] = new SchemaError($relation->line, "{$where} is defined as itself.");
                } elseif ($type->relation($node->relation) === null) {
                    $errors[] = new SchemaError($relation->line, "{$where} refers to `{$node->relation}`, which `{$type->name}` does not define.");
                }

                return;
            }

            if ($node instanceof RelationFromTupleset) {
                $errors = [...$errors, ...$this->tupleset($schema, $type, $relation, $node, $where)];
            }
        });

        if ($lists > 1) {
            $errors[] = new SchemaError($relation->line, "{$where} has more than one `[...]` list — merge them into one.");
        }

        return $errors;
    }

    /**
     * @return list<SchemaError>
     */
    private function tupleset(AuthorizationSchema $schema, TypeDefinition $type, RelationDefinition $relation, RelationFromTupleset $node, string $where): array
    {
        $tupleset = $type->relation($node->tupleset);

        if ($tupleset === null) {
            return [new SchemaError($relation->line, "{$where} inherits from `{$node->tupleset}`, which `{$type->name}` does not define.")];
        }

        if (! $tupleset->rewrite instanceof DirectlyRelated) {
            return [new SchemaError($relation->line, "{$where} inherits through `{$node->tupleset}`, which must be a plain list of types like `[folder]` — not computed from other relations.")];
        }

        foreach ($tupleset->rewrite->types as $target) {
            if ($target->relation !== null) {
                return [new SchemaError($relation->line, "{$where} inherits through `{$node->tupleset}`, which lists the userset `{$target->toDsl()}`; a relation you inherit through may only list types like `[folder]`.")];
            }
        }

        foreach ($tupleset->rewrite->types as $target) {
            if ($schema->relation($target->type, $node->relation) !== null) {
                return [];
            }
        }

        return [new SchemaError($relation->line, "{$where} inherits `{$node->relation}` from `{$node->tupleset}`, but no type `{$node->tupleset}` points at defines `{$node->relation}`.")];
    }

    /**
     * Every relation whose subtracted side depends — through any chain — on the relation
     * itself.
     *
     * @return list<SchemaError>
     */
    private function negativeCycles(AuthorizationSchema $schema): array
    {
        $errors = [];

        foreach ($schema->types as $type) {
            foreach ($type->relations as $relation) {
                $self = $type->name.'#'.$relation->name;

                foreach ($schema->dependencies($type->name, $relation->name) as $edge) {
                    if (! $edge['negative']) {
                        continue;
                    }

                    $target = $edge['type'].'#'.$edge['relation'];

                    if ($target === $self || $this->reaches($schema, $edge['type'], $edge['relation'], $self)) {
                        $errors[] = new SchemaError($relation->line, "`{$relation->name}` on `{$type->name}` subtracts `{$target}`, which depends on `{$self}` itself — an exclusion cannot refer back to the relation it decides.");

                        break;
                    }
                }
            }
        }

        return $errors;
    }

    private function reaches(AuthorizationSchema $schema, string $type, string $relation, string $goal): bool
    {
        $seen = [];
        $stack = [[$type, $relation]];

        while ($stack !== []) {
            [$t, $r] = array_pop($stack);
            $key = $t.'#'.$r;

            if ($key === $goal) {
                return true;
            }

            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;

            foreach ($schema->dependencies($t, $r) as $edge) {
                $stack[] = [$edge['type'], $edge['relation']];
            }
        }

        return false;
    }

    /**
     * @param  callable(Rewrite): void  $visit
     */
    private function walk(Rewrite $node, callable $visit): void
    {
        $visit($node);

        foreach ($node->children() as $child) {
            $this->walk($child, $visit);
        }
    }
}
