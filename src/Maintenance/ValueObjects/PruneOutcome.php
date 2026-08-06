<?php

declare(strict_types=1);

namespace Cbox\Id\Maintenance\ValueObjects;

use Cbox\Id\Maintenance\Enums\PrunableTable;
use Illuminate\Support\Carbon;

/**
 * What one table's sweep did — reported by the command, asserted on by tests, and
 * returned rather than logged so the caller decides how loud to be.
 *
 * A skipped table is not a failure: a host that only installs part of the platform
 * genuinely has no `provisioning_operations`, and an operator may deliberately set a
 * table's retention to null to keep its rows forever.
 */
final readonly class PruneOutcome
{
    private function __construct(
        public PrunableTable $table,
        public int $deleted,
        public ?int $retentionDays,
        public ?Carbon $cutoff,
        public ?string $skippedReason,
    ) {}

    public static function pruned(PrunableTable $table, int $deleted, int $retentionDays, Carbon $cutoff): self
    {
        return new self($table, $deleted, $retentionDays, $cutoff, null);
    }

    public static function skipped(PrunableTable $table, string $reason): self
    {
        return new self($table, 0, null, null, $reason);
    }

    public function wasSkipped(): bool
    {
        return $this->skippedReason !== null;
    }
}
