<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

/**
 * `[user, group#member]` — the subjects a tuple may name on this relation. The only node a
 * tuple can be WRITTEN against; every other node is computed from tuples on other relations.
 */
final readonly class DirectlyRelated implements Rewrite
{
    /**
     * @param  list<DirectType>  $types
     */
    public function __construct(public array $types) {}

    public function allows(string $type, ?string $relation): bool
    {
        foreach ($this->types as $allowed) {
            if ($allowed->matches($type, $relation)) {
                return true;
            }
        }

        return false;
    }

    public function toArray(): array
    {
        return ['direct' => array_map(static fn (DirectType $type): array => $type->toArray(), $this->types)];
    }

    public function toDsl(bool $nested = false): string
    {
        return '['.implode(', ', array_map(static fn (DirectType $type): string => $type->toDsl(), $this->types)).']';
    }

    public function children(): array
    {
        return [];
    }
}
