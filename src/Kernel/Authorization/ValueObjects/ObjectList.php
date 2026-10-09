<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

/**
 * The answer to a list query — the resources a subject can reach, or the subjects that
 * can reach a resource — as ids of the one type asked about, sorted, one page at a time.
 */
final readonly class ObjectList
{
    /**
     * @param  list<string>  $ids
     */
    public function __construct(
        public string $type,
        public array $ids,
        public ?string $nextCursor,
        public ConsistencyToken $consistency,
    ) {}

    public function hasMore(): bool
    {
        return $this->nextCursor !== null;
    }
}
