<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Console;

use Cbox\Id\Kernel\Audit\AuditServiceProvider;
use Cbox\Id\Kernel\Audit\Checkpointer;
use Cbox\Id\Kernel\Audit\ValueObjects\ChainCheckpoint;
use Illuminate\Console\Command;

/**
 * `cbox-id:audit:checkpoint` — sign a checkpoint over every audit chain that has
 * advanced since its last one.
 *
 * Registered on the scheduler by {@see AuditServiceProvider} ONLY when
 * `audit.checkpoint.schedule` is true, and that flag defaults to FALSE. Read
 * {@see Checkpointer} before turning it on: the first signature is a one-way door
 * that forecloses the one-time re-chain the GDPR-erasure design needs.
 *
 * `--dry-run` reports which chains would be signed and at which sequence, which is
 * the right first move on a deployment that has never been checkpointed — it is also
 * how to read off the head sequences you must retain out of band before any re-chain.
 */
class CheckpointCommand extends Command
{
    protected $signature = 'cbox-id:audit:checkpoint
        {--environment=* : Only these environments (default: all)}
        {--scope=* : Only these chains — an organization id, or __system__ (default: all)}
        {--force : Sign even when the chain has not advanced since its last checkpoint}
        {--dry-run : Report what would be signed, sign nothing}';

    protected $description = 'Sign a checkpoint over each audit chain, so tail deletion becomes detectable.';

    public function handle(Checkpointer $checkpointer): int
    {
        $dryRun = $this->option('dry-run') === true;

        if ($dryRun) {
            $this->comment('Dry run — nothing will be signed.');
        }

        $outcomes = $checkpointer->checkpointAll(
            dryRun: $dryRun,
            force: $this->option('force') === true,
            environmentIds: $this->values('environment'),
            scopes: $this->values('scope'),
        );

        if ($outcomes === []) {
            $this->info('No audit chains to checkpoint.');

            return self::SUCCESS;
        }

        $signed = 0;
        $failed = 0;

        foreach ($outcomes as $outcome) {
            if ($outcome->hasFailed()) {
                $failed++;
            } elseif (! $outcome->wasSkipped()) {
                $signed++;
            }
        }

        $this->table(
            ['Environment', 'Scope', 'Head', 'Last checkpoint', $dryRun ? 'Would sign' : 'Signed'],
            array_map(fn (ChainCheckpoint $outcome): array => $this->row($outcome), $outcomes),
        );

        $this->info(($dryRun ? 'Would sign ' : 'Signed ').$signed.' checkpoint(s) over '.count($outcomes).' chain(s).');

        // Stated every run, because a checkpoint is not just another maintenance
        // artefact: it is the thing a later re-chain cannot contradict.
        $this->line('<fg=gray>A signed checkpoint is permanent evidence. Re-chaining audit_logs after this point (e.g. the GDPR ciphertext-hashing migration) would make every retained checkpoint report tampering — see UPGRADING.md.</>');

        if ($failed > 0) {
            // Non-zero, so a scheduler or a probe sees it. The chains that COULD be
            // signed were signed — a chain nobody can attest is the thing to fix, and
            // leaving the rest unattested as well would not help anyone.
            $this->error($failed.' chain(s) could not be checkpointed.');

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /**
     * @return list<string>
     */
    private function values(string $option): array
    {
        /** @var list<string> $values */
        $values = array_values(array_filter(
            (array) $this->option($option),
            static fn (mixed $value): bool => is_string($value) && $value !== '',
        ));

        return $values;
    }

    /**
     * @return list<string>
     */
    private function row(ChainCheckpoint $outcome): array
    {
        return [
            $outcome->environmentId,
            $outcome->scope,
            (string) $outcome->headSequence,
            $outcome->checkpointedSequence === null ? 'never' : (string) $outcome->checkpointedSequence,
            match (true) {
                $outcome->hasFailed() => 'FAILED ('.$outcome->failureReason.')',
                $outcome->wasSkipped() => 'skipped ('.$outcome->skippedReason.')',
                default => 'yes, at '.$outcome->headSequence,
            },
        ];
    }
}
