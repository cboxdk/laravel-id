<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\ValueObjects;

/**
 * What one pass of `cbox-id:crypto:rewrap` did to one sealed column.
 *
 * `remaining` is read AFTER the pass: zero means every value in the column is sealed
 * under the current key. `failed` are values no configured key opened under the
 * column's context — they are left untouched, never overwritten, and keep the column out
 * of "done" until someone looks at them (`failedKeys` names the first few rows).
 */
readonly class RewrapOutcome
{
    /**
     * @param  list<string>  $failedKeys  the key values of the first rows that failed, for the operator
     */
    public function __construct(
        public SealedColumn $column,
        public int $rewrapped = 0,
        public int $failed = 0,
        public int $remaining = 0,
        public bool $dryRun = false,
        public bool $skipped = false,
        public array $failedKeys = [],
    ) {}

    public static function skipped(SealedColumn $column): self
    {
        return new self($column, skipped: true);
    }
}
