<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Contracts;

use Cbox\Id\Kernel\Audit\Models\AuditCheckpoint;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Audit\ValueObjects\ChainVerification;

/**
 * Append-only, hash-chained audit trail.
 *
 * Each entry chains to the previous via `hash = SHA256(canonical(entry) ‖ prev_hash)`,
 * so any later mutation of a recorded entry breaks the chain and is detectable.
 *
 * Honest scope of the guarantee: this is tamper-*evident*, not tamper-*proof*.
 * An attacker who can rewrite the whole table could recompute the chain. Real
 * anti-tamper rests on {@see checkpoint()}, whose signed roots should be anchored
 * to an external, append-only store. And the chain proves *integrity*, not
 * *completeness* — logging coverage is a separate obligation (see docs).
 */
interface AuditLog
{
    /**
     * Append an event to its scope's chain (tenant trail, or system trail when
     * the event has no organization).
     */
    public function record(AuditEvent $event): AuditEntry;

    /**
     * Verify a scope's chain segment: recomputes each entry's hash, and checks
     * sequence continuity and prev-hash linkage. `null` organization = system trail.
     */
    public function verifyChain(?string $organizationId = null, int $fromSequence = 1, ?int $toSequence = null): ChainVerification;

    /**
     * The sequence number of the newest entry in a scope's chain, or 0 when it has none.
     *
     * Exists so a caller can verify a WINDOW. `verifyChain()` reads and re-hashes every
     * row in its range, which is the right behaviour for an auditor and the wrong one for
     * a page that renders on every keystroke: without a way to ask where the chain ends,
     * the only window anyone can name is "all of it".
     */
    public function headSequence(?string $organizationId = null): int;

    /**
     * Produce a signed checkpoint over the current chain head for a scope, so its
     * root can be anchored externally. `null` organization = system trail.
     */
    public function checkpoint(?string $organizationId = null): AuditCheckpoint;
}
