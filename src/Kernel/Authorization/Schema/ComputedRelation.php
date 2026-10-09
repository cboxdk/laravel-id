<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

/**
 * `owner` inside `relation editor: [user] or owner` — whoever has that other relation on
 * the SAME object has this one too (a computed userset).
 */
final readonly class ComputedRelation implements Rewrite
{
    public function __construct(public string $relation) {}

    public function toArray(): array
    {
        return ['computed' => $this->relation];
    }

    public function toDsl(bool $nested = false): string
    {
        return $this->relation;
    }

    public function children(): array
    {
        return [];
    }
}
