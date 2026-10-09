<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

/**
 * One relation on a type: its name and how it is decided.
 */
final readonly class RelationDefinition
{
    /**
     * @param  int  $line  where it was written in the schema source; 0 once loaded from storage
     */
    public function __construct(
        public string $name,
        public Rewrite $rewrite,
        public int $line = 0,
    ) {}

    /**
     * The subjects a tuple may name on this relation, or null for a relation that is only
     * ever computed (no tuple can be written to it). A relation has at most one such list.
     */
    public function directlyRelated(): ?DirectlyRelated
    {
        return self::findDirect($this->rewrite);
    }

    /**
     * @return array{name: string, rewrite: array<string, mixed>, directly_related: list<array{type: string, relation?: string}>}
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'rewrite' => $this->rewrite->toArray(),
            'directly_related' => array_map(
                static fn (DirectType $type): array => $type->toArray(),
                $this->directlyRelated()->types ?? [],
            ),
        ];
    }

    private static function findDirect(Rewrite $node): ?DirectlyRelated
    {
        if ($node instanceof DirectlyRelated) {
            return $node;
        }

        foreach ($node->children() as $child) {
            $found = self::findDirect($child);

            if ($found !== null) {
                return $found;
            }
        }

        return null;
    }
}
