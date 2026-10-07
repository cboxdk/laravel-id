<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Contracts;

use Cbox\Id\Kernel\Crypto\ValueObjects\RewrapOutcome;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;
use Closure;

/**
 * Moves sealed secrets onto the current master key — the second half of a key rotation.
 *
 * RESUMABLE BY CONSTRUCTION. A pass only ever selects values that are not yet under the
 * current key, walking the table by its key in bounded chunks, and writes each value
 * back only if it is still what it read. So an interrupted run, a re-run, or two runs at
 * once all converge on the same end state without redoing or clobbering anything.
 */
interface SecretRewrapper
{
    /**
     * Re-seal every value in one column that is not yet under the current key.
     *
     * @param  int  $chunk  rows read per query
     * @param  bool  $dryRun  count what would be re-sealed, write nothing
     * @param  (Closure(int $processed): void)|null  $progress  called after each chunk with the running count
     */
    public function rewrap(SealedColumn $column, int $chunk = 500, bool $dryRun = false, ?Closure $progress = null): RewrapOutcome;

    /**
     * How many values in a column are not yet under the current key: sealed under a
     * previous key, or untagged envelopes from before key versioning. Zero for a column
     * whose table does not exist.
     */
    public function remaining(SealedColumn $column): int;
}
