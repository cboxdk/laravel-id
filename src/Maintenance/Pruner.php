<?php

declare(strict_types=1);

namespace Cbox\Id\Maintenance;

use Cbox\Id\Kernel\Audit\DatabaseAuditLog;
use Cbox\Id\Maintenance\Enums\PrunableTable;
use Cbox\Id\Maintenance\ValueObjects\PruneOutcome;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Schema;

/**
 * Deletes rows that have outlived their purpose, in bounded chunks.
 *
 * Before this existed the platform had no delete path AT ALL: twelve console commands
 * and not one of them removed a row. `dpop_proofs` alone takes one INSERT per
 * DPoP-protected request and carries a unique index that grows with total request
 * volume, forever.
 *
 * ## Why `audit_logs` is NOT pruned
 *
 * `audit_logs` is a hash-chained, tamper-evident structure, not a log file.
 * {@see DatabaseAuditLog::verifyChain()} walks from
 * `fromSequence` (default 1) and reports `sequence gap or reordering` the moment a
 * row is missing, and
 * {@see DatabaseAuditLog::verifyCheckpointAnchor()} deliberately
 * exists to catch tail deletion by requiring the entry anchored by the last signed
 * checkpoint to still be present with the same hash.
 *
 * So there is no "prune up to a verified checkpoint" that leaves verification intact:
 * pruning BELOW a checkpoint breaks the default full-chain verify, and pruning UP TO
 * AND INCLUDING one removes the anchor row the tamper check reads — which is precisely
 * the deletion the anchor check is designed to detect. A prune that makes the
 * tamper-evidence report tampering has destroyed the control.
 *
 * Bounding audit growth is a real need, but it needs a different mechanism — export to
 * the audit stream (`src/AuditStreaming/`), then a rechaining or archive step that
 * re-anchors the surviving prefix and signs the new genesis. That is a feature, not a
 * sweep, and it is deliberately out of scope here rather than approximated unsafely.
 *
 * The sweep runs UNSCOPED by environment on purpose. It is a deployment-wide
 * maintenance pass (the same posture as the outbox relay), so it uses the raw query
 * builder and never the environment-owned Eloquent models, whose global scope would
 * silently narrow every delete to whichever environment the scheduler happened to be in.
 */
class Pruner
{
    /** Rows deleted per statement — bounded so a sweep never takes a table-wide lock. */
    public const DEFAULT_CHUNK = 1000;

    /**
     * Sweep every table, in enum order.
     *
     * @return list<PruneOutcome>
     */
    public function pruneAll(?int $chunk = null, bool $dryRun = false): array
    {
        return array_map(
            fn (PrunableTable $table): PruneOutcome => $this->prune($table, $chunk, $dryRun),
            PrunableTable::cases(),
        );
    }

    public function prune(PrunableTable $table, ?int $chunk = null, bool $dryRun = false): PruneOutcome
    {
        $retention = $this->retentionDays($table);

        if ($retention === null) {
            return PruneOutcome::skipped($table, 'retention disabled in config');
        }

        // A host may install only part of the platform (the builtin-RBAC tables are
        // already gated this way), so an absent table is expected, not an error.
        if (! Schema::hasTable($table->value)) {
            return PruneOutcome::skipped($table, 'table not present');
        }

        $cutoff = Carbon::now()->subDays($retention);
        $size = $this->chunkSize($chunk);
        $key = $table->keyColumn();

        if ($dryRun) {
            return PruneOutcome::pruned($table, $table->deadRows($cutoff)->count(), $retention, $cutoff);
        }

        $deleted = 0;

        // Select a page of keys, then delete by key. `DELETE ... LIMIT` is a
        // MySQL/SQLite extension that Postgres rejects, and an unbounded
        // `DELETE WHERE expires_at < ?` on a table that has never been swept would
        // take one enormous transaction on its first run.
        while (true) {
            /** @var list<mixed> $keys */
            $keys = $table->deadRows($cutoff)->limit($size)->pluck($key)->all();

            if ($keys === []) {
                break;
            }

            $deleted += $table->deadRows($cutoff)->whereIn($key, $keys)->delete();

            if (count($keys) < $size) {
                break;
            }
        }

        return PruneOutcome::pruned($table, $deleted, $retention, $cutoff);
    }

    /**
     * Days of retention for a table, or null when the operator has turned this
     * table's sweep off (an explicit `null` in config — NOT a missing key, which
     * falls back to the table's own default).
     */
    private function retentionDays(PrunableTable $table): ?int
    {
        /** @var array<string, mixed> $configured */
        $configured = (array) config('cbox-id.prune.retention_days', []);

        if (! array_key_exists($table->value, $configured)) {
            return $table->defaultRetentionDays();
        }

        $value = $configured[$table->value];

        if ($value === null || $value === '' || $value === false) {
            return null;
        }

        return is_numeric($value) ? max(0, (int) $value) : $table->defaultRetentionDays();
    }

    private function chunkSize(?int $chunk): int
    {
        if ($chunk !== null) {
            return max(1, $chunk);
        }

        $configured = config('cbox-id.prune.chunk', self::DEFAULT_CHUNK);

        return is_numeric($configured) ? max(1, (int) $configured) : self::DEFAULT_CHUNK;
    }
}
