<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

/**
 * One resource type (`document`, `folder`, `user`) and the relations defined on it. A type
 * with no relations is still a type: `user` usually has none, and is only ever a subject.
 */
final readonly class TypeDefinition
{
    /**
     * @param  array<string, RelationDefinition>  $relations  by name, in written order
     */
    public function __construct(
        public string $name,
        public array $relations = [],
        public int $line = 0,
    ) {}

    public function relation(string $name): ?RelationDefinition
    {
        return $this->relations[$name] ?? null;
    }

    /**
     * @return array{name: string, relations: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'relations' => array_values(array_map(static fn (RelationDefinition $relation): array => $relation->toArray(), $this->relations)),
        ];
    }
}
