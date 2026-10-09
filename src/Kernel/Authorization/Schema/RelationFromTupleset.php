<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

/**
 * `viewer from parent` — whoever is a `viewer` of any object this one's `parent` tuples
 * point at (a tuple-to-userset). How a document inherits from its folder, and a folder
 * from the folder above it.
 */
final readonly class RelationFromTupleset implements Rewrite
{
    public function __construct(
        public string $relation,
        public string $tupleset,
    ) {}

    public function toArray(): array
    {
        return ['from' => ['tupleset' => $this->tupleset, 'relation' => $this->relation]];
    }

    public function toDsl(bool $nested = false): string
    {
        return $this->relation.' from '.$this->tupleset;
    }

    public function children(): array
    {
        return [];
    }
}
