<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/**
 * The outcome of a bulk import: how many users were created, updated (upsert), or
 * skipped (already present, no upsert), plus the per-row errors that were
 * collected instead of aborting the run.
 */
final readonly class ImportResult
{
    /**
     * @param  list<ImportError>  $errors
     */
    public function __construct(
        public int $imported,
        public int $updated,
        public int $skipped,
        public array $errors,
    ) {}

    public function errorCount(): int
    {
        return count($this->errors);
    }

    /** Whether any row failed — the signal a CLI maps to a non-zero exit. */
    public function failed(): bool
    {
        return $this->errors !== [];
    }

    /** Total rows seen across every outcome. */
    public function total(): int
    {
        return $this->imported + $this->updated + $this->skipped + $this->errorCount();
    }
}
