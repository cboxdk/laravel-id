<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit;

use Cbox\Id\Kernel\Audit\Console\CheckpointCommand;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\ChainCheckpoint;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * Signs a checkpoint over every audit chain that has advanced since its last one.
 *
 * ## What a checkpoint is for
 *
 * The hash chain detects MODIFICATION and sequence GAPS on its own. It cannot detect
 * TRUNCATION: delete the newest N entries and what remains is a shorter, perfectly
 * valid chain. {@see DatabaseAuditLog::verifyChain()} closes that hole only through
 * a signed checkpoint — the entry a checkpoint anchors must still be present with the
 * same hash — so an audit trail with NO checkpoints has no tail-deletion detection at
 * all. Until this class existed, nothing in the platform ever called
 * {@see AuditLog::checkpoint()}: `audit_checkpoints` was empty everywhere.
 *
 * ## THIS IS NOT SCHEDULED BY DEFAULT, AND THAT IS DELIBERATE
 *
 * `audit.checkpoint.schedule` defaults to FALSE. Signing the first checkpoint is a
 * ONE-WAY DOOR: from that moment the chain's current hashes are attested by a
 * signature that may already have been exported to an external, append-only store,
 * and any later re-chaining would make every retained checkpoint report tampering
 * that did not happen. The planned GDPR-erasure design needs exactly one re-chain
 * (hash the CIPHERTEXT of `ip`/`context` rather than the plaintext, so destroying a
 * per-subject key leaves every hashed byte unchanged). While no checkpoint has ever
 * been signed there is nothing for that re-chain to contradict, and that window
 * closes permanently the first time this runs.
 *
 * The ordering, which is written out in UPGRADING.md and docs/operations:
 *
 *   1. sign and retain each chain's current head hash and row count OUT OF BAND;
 *   2. introduce `chain_version` and ciphertext hashing;
 *   3. run the one-time re-chain;
 *   4. THEN turn `audit.checkpoint.schedule` on.
 *
 * A deployment with no such migration ahead of it can enable it today — that is the
 * point of it being a config flag rather than a comment.
 *
 * ## Safety
 *
 * Idempotent: a chain whose head is already attested is skipped, so re-running adds
 * nothing. Safe alongside live appends: it takes no lock and writes no `audit_logs`
 * row, and an append that lands mid-pass simply belongs to the next checkpoint.
 * Two overlapping passes can at worst sign the same head twice, which is harmless —
 * {@see DatabaseAuditLog::verifyChain()} reads the highest checkpoint.
 *
 * Enumeration is environment-SPANNING, so it uses the raw query builder rather than
 * the environment-owned models (the same posture as the outbox relay and the prune
 * sweep), then re-enters each chain's own environment to sign. Chains are read from
 * `audit_logs` itself rather than from the environments table on purpose: that is
 * exactly the set of chains that exist, and it includes the platform plane, which
 * has no environment row at all.
 *
 * @see CheckpointCommand
 */
class Checkpointer
{
    /**
     * Resolves the environment context per call rather than holding it: this is a
     * singleton, that binding is `scoped`, and a captured one would keep the first
     * queue job's environment for the life of the process.
     */
    use ResolvesEnvironment;

    public function __construct(
        private readonly AuditLog $log,
    ) {}

    /**
     * Checkpoint every chain, oldest environment first.
     *
     * @param  list<string>  $environmentIds  restrict to these environments (empty: all)
     * @param  list<string>  $scopes  restrict to these scopes (empty: all)
     * @return list<ChainCheckpoint>
     */
    public function checkpointAll(bool $dryRun = false, bool $force = false, array $environmentIds = [], array $scopes = []): array
    {
        $attested = $this->attestedSequences();

        return array_map(
            function (array $chain) use ($attested, $dryRun, $force): ChainCheckpoint {
                [$environmentId, $scope, $head] = $chain;

                return $this->checkpointChain(
                    $environmentId,
                    $scope,
                    $head,
                    $attested[$this->key($environmentId, $scope)] ?? null,
                    $dryRun,
                    $force,
                );
            },
            $this->chains($environmentIds, $scopes),
        );
    }

    private function checkpointChain(string $environmentId, string $scope, int $head, ?int $attested, bool $dryRun, bool $force): ChainCheckpoint
    {
        // Nothing appended since the last checkpoint: another signature over the same
        // head would attest exactly what the previous one already attests.
        if (! $force && $attested !== null && $attested >= $head) {
            return ChainCheckpoint::skipped($environmentId, $scope, $head, $attested, 'already checkpointed at head');
        }

        if ($dryRun) {
            return ChainCheckpoint::pending($environmentId, $scope, $head, $attested);
        }

        try {
            // Re-enter the chain's own environment: checkpoint() resolves the
            // environment from context (never from an argument), and the checkpoint row
            // it writes is environment-owned. Signing env A's chain from env B's
            // context would either anchor the wrong chain or be refused outright.
            $checkpoint = $this->environments()->runAs(
                GenericEnvironment::of($environmentId),
                fn () => $this->log->checkpoint($scope === DatabaseAuditLog::SYSTEM_SCOPE ? null : $scope),
            );
        } catch (Throwable $failure) {
            // Recorded, not thrown: a deployment has one chain per organization, and a
            // single unsignable one (a missing signing key for its environment, say)
            // must not stop every chain after it in the pass. The command prints the
            // reason and exits non-zero, so it is still loud.
            return ChainCheckpoint::failed($environmentId, $scope, $head, $attested, $failure::class.': '.$failure->getMessage());
        }

        return ChainCheckpoint::signed($environmentId, $scope, $checkpoint->up_to_sequence, $attested, $checkpoint->id);
    }

    /**
     * Every (environment, scope) chain that has at least one entry, with its head.
     *
     * @param  list<string>  $environmentIds
     * @param  list<string>  $scopes
     * @return list<array{string, string, int}>
     */
    private function chains(array $environmentIds, array $scopes): array
    {
        $query = DB::table('audit_logs')
            ->select('environment_id', 'scope')
            ->selectRaw('max(sequence) as head_sequence')
            ->groupBy('environment_id', 'scope')
            ->orderBy('environment_id')
            ->orderBy('scope');

        if ($environmentIds !== []) {
            $query->whereIn('environment_id', $environmentIds);
        }

        if ($scopes !== []) {
            $query->whereIn('scope', $scopes);
        }

        $chains = [];

        foreach ($query->get() as $row) {
            $environmentId = $row->environment_id ?? null;
            $scope = $row->scope ?? null;
            $head = $row->head_sequence ?? null;

            if (! is_string($environmentId) || ! is_string($scope) || ! is_numeric($head)) {
                continue;
            }

            $chains[] = [$environmentId, $scope, (int) $head];
        }

        return $chains;
    }

    /**
     * The highest sequence already attested for each chain.
     *
     * @return array<string, int>
     */
    private function attestedSequences(): array
    {
        $rows = DB::table('audit_checkpoints')
            ->select('environment_id', 'scope')
            ->selectRaw('max(up_to_sequence) as attested_sequence')
            ->groupBy('environment_id', 'scope')
            ->get();

        $attested = [];

        foreach ($rows as $row) {
            $environmentId = $row->environment_id ?? null;
            $scope = $row->scope ?? null;
            $sequence = $row->attested_sequence ?? null;

            if (! is_string($environmentId) || ! is_string($scope) || ! is_numeric($sequence)) {
                continue;
            }

            $attested[$this->key($environmentId, $scope)] = (int) $sequence;
        }

        return $attested;
    }

    /**
     * A chain's map key. The separator is a NUL byte because neither an environment
     * key nor a scope can contain one, so no two chains can ever collide on it.
     */
    private function key(string $environmentId, string $scope): string
    {
        return $environmentId."\0".$scope;
    }
}
