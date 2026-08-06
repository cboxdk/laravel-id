<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\ValueObjects;

use Cbox\Id\Kernel\Audit\Checkpointer;

/**
 * What one chain's checkpoint pass did — returned rather than logged, so the caller
 * decides how loud to be, and so tests can assert on it without parsing output.
 *
 * A skipped chain is the NORMAL outcome, not a failure: a chain that has not been
 * appended to since its last checkpoint has nothing new to attest, and signing it
 * again would add a row that says exactly what the previous row already says.
 *
 * @see Checkpointer
 */
final readonly class ChainCheckpoint
{
    private function __construct(
        public string $environmentId,
        /** The organization id, or `__system__` for the environment's own trail. */
        public string $scope,
        /** The chain's current head — the sequence a checkpoint would attest. */
        public int $headSequence,
        /** The highest sequence already attested by a signed checkpoint, if any. */
        public ?int $checkpointedSequence,
        /** The checkpoint row that was written, or null on a dry run, skip or failure. */
        public ?string $checkpointId,
        public ?string $skippedReason,
        public ?string $failureReason,
    ) {}

    public static function signed(string $environmentId, string $scope, int $headSequence, ?int $checkpointedSequence, string $checkpointId): self
    {
        return new self($environmentId, $scope, $headSequence, $checkpointedSequence, $checkpointId, null, null);
    }

    /** A dry run: this chain WOULD have been signed at `headSequence`. */
    public static function pending(string $environmentId, string $scope, int $headSequence, ?int $checkpointedSequence): self
    {
        return new self($environmentId, $scope, $headSequence, $checkpointedSequence, null, null, null);
    }

    public static function skipped(string $environmentId, string $scope, int $headSequence, ?int $checkpointedSequence, string $reason): self
    {
        return new self($environmentId, $scope, $headSequence, $checkpointedSequence, null, $reason, null);
    }

    /**
     * Signing this chain threw. Recorded per chain rather than thrown, so one
     * unsignable chain cannot silently stop the pass before the rest — the command
     * reports it and exits non-zero.
     */
    public static function failed(string $environmentId, string $scope, int $headSequence, ?int $checkpointedSequence, string $reason): self
    {
        return new self($environmentId, $scope, $headSequence, $checkpointedSequence, null, null, $reason);
    }

    public function wasSkipped(): bool
    {
        return $this->skippedReason !== null;
    }

    public function wasSigned(): bool
    {
        return $this->checkpointId !== null;
    }

    public function hasFailed(): bool
    {
        return $this->failureReason !== null;
    }
}
