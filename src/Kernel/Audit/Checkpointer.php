<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit;

use Cbox\AuditChain\Checkpointer as PackageCheckpointer;
use Cbox\AuditChain\Storage\DatabaseChainInventory;
use Cbox\AuditChain\ValueObjects\ChainFilter;
use Cbox\AuditChain\ValueObjects\CheckpointOutcome;
use Cbox\Id\Kernel\Audit\Chain\AuditLogChain;
use Cbox\Id\Kernel\Audit\Chain\AuditStorage;
use Cbox\Id\Kernel\Audit\Chain\EnvironmentChainContext;
use Cbox\Id\Kernel\Audit\Console\CheckpointCommand;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\ChainCheckpoint;

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
 * ## Where the pass lives
 *
 * The pass itself is cboxdk/laravel-audit-chain's {@see PackageCheckpointer}, which
 * this class drives over the platform's pieces: the {@see AuditLog} it was given (so a
 * decorated or failing log behaves exactly as before), the `audit_logs` inventory, and
 * a chain context that re-enters each chain's environment. The outcomes are the same
 * {@see ChainCheckpoint}s as ever.
 *
 * @see CheckpointCommand
 */
class Checkpointer
{
    /**
     * The environment context is resolved per call inside {@see EnvironmentChainContext}
     * rather than held: this is a singleton, that binding is `scoped`, and a captured one
     * would keep the first queue job's environment for the life of the process.
     */
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
        $context = new EnvironmentChainContext;

        // The platform's own tables, stated rather than resolved: the package's
        // ChainInventory binding is the host's to change, the platform's trail is not.
        $inventory = new DatabaseChainInventory(AuditStorage::models());

        $pass = new PackageCheckpointer(new AuditLogChain($this->log, $context), $inventory, $context);

        return array_map(
            static fn (CheckpointOutcome $outcome): ChainCheckpoint => ChainCheckpoint::fromOutcome($outcome),
            $pass->checkpointAll($dryRun, $force, new ChainFilter($environmentIds, $scopes)),
        );
    }
}
