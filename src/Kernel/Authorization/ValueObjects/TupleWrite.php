<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

/**
 * What a tuple batch changed: how many of its writes were new and how many of its deletes
 * removed something (re-writing an existing tuple, or deleting a missing one, changes
 * nothing and is not an error), and the revision to check against afterwards.
 */
final readonly class TupleWrite
{
    public function __construct(
        public int $written,
        public int $deleted,
        public ConsistencyToken $consistency,
    ) {}
}
