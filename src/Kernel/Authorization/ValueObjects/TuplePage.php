<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

/**
 * A page of stored tuples, oldest first, with the cursor to the next page.
 */
final readonly class TuplePage
{
    /**
     * @param  list<Tuple>  $tuples
     */
    public function __construct(
        public array $tuples,
        public ?string $nextCursor,
        public ConsistencyToken $consistency,
    ) {}
}
