<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\ValueObjects;

/**
 * The outcome of a directory pull: how many users were provisioned (created or
 * updated) and how many were deprovisioned (present before, gone from the provider).
 *
 * An HR-system pull also reports what it skipped (no work email, not started yet, a leaver
 * who never had an account), what it could not reconcile ({@see SyncFailure}), and whether
 * it was incremental — an incremental run asks only for what changed, so it never
 * deprovisions anybody for being absent.
 */
readonly class DirectorySyncResult
{
    /**
     * @param  list<SyncFailure>  $failures  at most `cbox-id.directory.hris.max_reported_failures` of them; `$failed` is the true count
     */
    public function __construct(
        public int $provisioned,
        public int $deprovisioned,
        public int $groupsSynced = 0,
        public int $skipped = 0,
        public int $failed = 0,
        public array $failures = [],
        public bool $incremental = false,
    ) {}

    /** Whether some records could not be reconciled, or a safety check held something back. */
    public function partial(): bool
    {
        return $this->failed > 0;
    }

    /**
     * The run as stored on `directories.last_sync_stats`.
     *
     * @return array{mode: string, provisioned: int, deprovisioned: int, groups: int, skipped: int, failed: int, failures: list<array{external_id: string|null, reason: string}>}
     */
    public function toArray(): array
    {
        return [
            'mode' => $this->incremental ? 'incremental' : 'full',
            'provisioned' => $this->provisioned,
            'deprovisioned' => $this->deprovisioned,
            'groups' => $this->groupsSynced,
            'skipped' => $this->skipped,
            'failed' => $this->failed,
            'failures' => array_map(static fn (SyncFailure $f): array => $f->toArray(), $this->failures),
        ];
    }
}
