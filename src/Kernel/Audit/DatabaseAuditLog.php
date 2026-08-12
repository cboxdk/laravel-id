<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Exceptions\CannotAppendToAuditChain;
use Cbox\Id\Kernel\Audit\Exceptions\CannotCheckpointEmptyScope;
use Cbox\Id\Kernel\Audit\Models\AuditCheckpoint;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Audit\ValueObjects\ChainVerification;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Scopes\EnvironmentScope;
use Illuminate\Database\DetectsConcurrencyErrors;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Throwable;

class DatabaseAuditLog implements AuditLog
{
    use DetectsConcurrencyErrors;

    /**
     * The scope of entries that belong to no organization — the environment's own
     * trail. Public because a chain is addressed by (environment, scope) from
     * outside too: {@see Checkpointer} enumerates the stored scopes and has to map
     * this one back to the `null` organization the contract speaks in.
     */
    public const SYSTEM_SCOPE = '__system__';

    /**
     * The environment key used for entries recorded OUTSIDE any environment — the
     * account-management plane deliberately runs without one.
     *
     * A literal sentinel rather than NULL, because SQL treats NULLs as distinct in a
     * unique index: with NULL, the (environment_id, scope, sequence) key never fired,
     * every platform-plane entry was written at sequence 1 with the genesis hash, and
     * the highest-privilege audit trail silently stopped being a chain at all.
     */
    public const PLATFORM_ENVIRONMENT = '__platform__';

    private const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * The chain position appenders serialise on. See record().
     */
    private const ANCHOR_SEQUENCE = 1;

    /**
     * How many times an append may re-read the head and re-claim a position before
     * giving up. Only the first entry of a chain can collide more than once (there
     * is no anchor to queue on yet), and that resolves in a single extra round, so
     * the budget is a margin, not the mechanism.
     *
     * Raised from 5 with the genesis fix: the ladder now also absorbs serialisation
     * failures, which Laravel used to retry on its own private budget of three. Eight
     * covers one contender per writer in the measured 8-process case even in the
     * worst ordering, and every attempt after the first sleeps a jittered backoff.
     */
    private const MAX_APPEND_ATTEMPTS = 8;

    /**
     * Ceiling, in milliseconds, on the jittered pause between append attempts.
     *
     * Retries are the resolution mechanism for a contended chain, so they must not
     * re-collide in lockstep: every retrier that woke from the same collision would
     * otherwise reach the insert at the same instant again.
     */
    private const MAX_BACKOFF_MILLISECONDS = 64;

    public function __construct(
        private readonly TokenSigner $signer,
    ) {}

    /**
     * The chain's environment dimension, resolved EXPLICITLY and LAZILY.
     *
     * Never taken from the global scope: a chain head read through an ambient scope
     * returns null when no environment is set (EnvironmentScope emits `1 = 0`), which
     * restarts the chain on every write instead of extending it.
     *
     * And never CAPTURED: `EnvironmentContext` is a `scoped` binding while this log is
     * a `singleton`. A queue worker's `forgetScopedInstances()` unsets the binding but
     * does not reset the object, so a captured manager keeps the first job's environment
     * for the life of the process — every later job would then append to the FIRST job's
     * chain, take a lock on the wrong chain head, and (because AuditEntry is
     * environment-owned) throw CrossEnvironmentAccess on save. Callers that report and
     * swallow that exception lose the audit entry silently while their transaction
     * commits. Resolving per call is the same rule EnvironmentScope::apply() states.
     */
    private function environmentKey(): string
    {
        return app(EnvironmentContext::class)->current()?->environmentKey() ?? self::PLATFORM_ENVIRONMENT;
    }

    /**
     * A chain query that ignores the ambient environment scope and states its own.
     *
     * @return Builder<AuditEntry>
     */
    private function chain(string $scope): Builder
    {
        return AuditEntry::query()
            ->withoutGlobalScope(EnvironmentScope::class)
            ->where('environment_id', $this->environmentKey())
            ->where('scope', $scope);
    }

    /**
     * Append one entry to the (environment, scope) chain.
     *
     * Two writers must not compute the same next sequence, and the append must not
     * be lost when they try. Both are handled here, in that order:
     *
     * 1. Appenders serialise on the chain's ANCHOR row (sequence 1) rather than on
     *    its head. Under READ COMMITTED a blocked `FOR UPDATE` re-checks its
     *    predicate against the row it was waiting on, NOT against the
     *    `ORDER BY sequence DESC LIMIT 1` that picked it — so a waiter on the head
     *    wakes still holding the OLD head and computes a sequence that has just
     *    been taken. The anchor's predicate is an equality on the unique key, so it
     *    cannot go stale: whoever holds it reads the head afterwards and sees the
     *    previous holder's committed entry. Measured on PostgreSQL 16, 8 writers x
     *    100 appends went from 100 written / 700 lost to 800 written / 0 lost.
     *
     * 2. The unique(environment_id, scope, sequence) violation is caught and the
     *    append RE-READS the head and retries. This covers the one window the
     *    anchor cannot: the first entry of a chain, where there is no anchor to
     *    lock yet. It converges in one extra round — after the first winner
     *    commits, every retrier finds the anchor and queues on it.
     *
     * 3. A SERIALISATION FAILURE (SQLSTATE 40001 / deadlock) is retried on the same
     *    ladder, with a jittered pause. This is the genesis race on InnoDB: see
     *    anchorId() for why an empty chain no longer takes a gap lock, and why a
     *    bounded retry is still kept behind that.
     *
     * The old `DB::transaction(..., attempts: 3)` did neither of the first two:
     * Laravel's ConcurrencyErrorDetector matches SQLSTATE 40001 and deadlock
     * messages, and a duplicate key is 23505 — so the transaction was never retried
     * and the entry was simply lost.
     *
     * Each attempt is a transaction of its own (`attempts: 1`) so that there is ONE
     * retry ladder rather than two nested ones. Laravel's own retry re-runs the
     * closure immediately, with no pause and no separate budget — which is exactly
     * how eight MariaDB writers spent all three attempts on the same gap.
     *
     * SCOPE OF THE RETRY. When record() is called inside a caller's transaction the
     * attempt is a savepoint, so a duplicate key still rolls back to it and retries
     * normally. A SERIALISATION failure there does not and must not: the engine has
     * already rolled the caller's whole transaction back, so Laravel raises a
     * DeadlockException (a PDOException, not a QueryException) and it passes straight
     * through this loop to the caller, who is the only one who can retry the unit of
     * work it belongs to.
     *
     * One thing no retry budget can fix, and it predates all of this: under
     * REPEATABLE READ, an append nested in a caller's transaction that has ALREADY
     * read `audit_logs` is answered from the caller's fixed snapshot, so a colliding
     * retry re-reads the same stale head and collides again. That ends in
     * CannotAppendToAuditChain rather than a lost or misplaced entry — the loud end
     * of the trade, and the right one.
     */
    public function record(AuditEvent $event): AuditEntry
    {
        $scope = $this->scopeFor($event->organizationId);

        for ($attempt = 1; ; $attempt++) {
            try {
                // Located BEFORE the transaction opens, and re-located on every
                // attempt. See appendOnce() for both halves of why.
                $anchorId = $this->anchorId($scope);

                return DB::transaction(fn (): AuditEntry => $this->appendOnce($event, $scope, $anchorId), attempts: 1);
            } catch (QueryException $collision) {
                if (! $this->isContention($collision)) {
                    throw $collision;
                }

                if ($attempt >= self::MAX_APPEND_ATTEMPTS) {
                    throw CannotAppendToAuditChain::afterAttempts($scope, self::MAX_APPEND_ATTEMPTS, $collision);
                }

                $this->backOff($attempt);
            }
        }
    }

    /**
     * Whether a failed append lost a race and may be re-tried, as opposed to being
     * a real error (a bad column, a dead connection) that must reach the caller.
     *
     * Two shapes count, and only these two: another writer took the position
     * (duplicate key), or the engine picked this transaction as the victim of a
     * lock cycle (SQLSTATE 40001 / 1213). Everything else is re-thrown untouched —
     * retrying a malformed statement eight times just delays the same failure.
     */
    private function isContention(QueryException $exception): bool
    {
        return $exception instanceof UniqueConstraintViolationException
            || $this->causedByConcurrencyError($exception);
    }

    /**
     * Pause for a random, growing interval before the next attempt.
     *
     * Randomised on purpose: contenders that all woke from the same collision and
     * slept the same fixed time would simply collide again, together.
     */
    private function backOff(int $attempt): void
    {
        // Doubles per attempt, capped. A shift rather than `2 **` so the exponent
        // cannot run away into a float.
        $ceiling = min(1 << min($attempt, 8), self::MAX_BACKOFF_MILLISECONDS);

        usleep(random_int(0, $ceiling) * 1000);
    }

    /**
     * One append attempt, inside its own transaction. Every attempt re-reads the
     * head — a retry that reused the stale head would collide forever.
     *
     * `$anchorId` is the chain's genesis row, or null when the chain has none yet.
     * It is found by the CALLER, outside this transaction, and that placement is
     * load-bearing on MySQL and MariaDB — see anchorId().
     */
    private function appendOnce(AuditEvent $event, string $scope, ?string $anchorId): AuditEntry
    {
        if ($anchorId !== null) {
            $this->lockAnchor($anchorId);
        }

        // Holding the anchor already excludes every other appender on this chain, so
        // the head read needs no lock of its own. And when there is no anchor to hold
        // (an empty chain, or one whose genesis row is gone) this deliberately takes
        // NO lock either: on an empty chain every locking read is a range predicate
        // that matches nothing, which InnoDB answers with a gap lock, which is the
        // deadlock. Step 2 above — the unique key plus a retry — is what makes the
        // unlocked read safe.
        $last = $this->headEntry($scope, lock: false);

        if ($last === null) {
            $prevHash = self::GENESIS_HASH;
            $sequence = 1;
        } else {
            $prevHash = $last->hash;
            $sequence = $last->sequence + 1;
        }

        $entry = new AuditEntry;
        $entry->fill([
            // Stamped explicitly: BelongsToEnvironment's saving hook returns early
            // when no environment is in context, which left this NULL.
            'environment_id' => $this->environmentKey(),
            'scope' => $scope,
            'organization_id' => $event->organizationId,
            'sequence' => $sequence,
            'actor_type' => $event->actorType,
            'actor_id' => $event->actorId,
            'action' => $event->action,
            'target_type' => $event->targetType,
            'target_id' => $event->targetId,
            'context' => $event->context,
            'ip' => $event->ip,
            'recorded_at' => now(),
        ]);
        $entry->prev_hash = $prevHash;
        $entry->hash = $this->computeHash($entry, $prevHash);
        $entry->save();

        return $entry;
    }

    /**
     * Find the chain's anchor — its genesis row (sequence 1) — or null if the chain
     * is empty. `audit_logs` is append-only and never pruned, so that row exists for
     * every non-empty chain, is never updated, and keeps its id forever.
     *
     * ## Why the anchor is FOUND unlocked, and found OUTSIDE the transaction
     *
     * The obvious spelling — one `where sequence = 1 … for update` inside the
     * transaction — is a locking read whose predicate matches NO ROW while the chain
     * is empty, and InnoDB answers that by locking the gap the row would have
     * occupied. Eight processes opening a brand-new chain each take that gap lock,
     * then each needs an insert-intention lock inside the very gap the other seven
     * hold. MariaDB 11.8 resolves the pile-up as SQLSTATE 40001 (error 1213) rather
     * than the duplicate key step 2 absorbs. Measured: 6 of 800 appends lost on
     * MariaDB 11.8.8, 800/800 on MySQL 8.4 and PostgreSQL 16 — the same statement,
     * a different deadlock detector. So the search is a PLAIN read and the lock is
     * taken separately, by PRIMARY KEY, on a row already known to exist: an exact
     * primary-key match takes a record lock and can never take a gap lock.
     *
     * That leaves WHERE the plain read runs, which is not a detail. MySQL and MariaDB
     * default to REPEATABLE READ, where a transaction's FIRST consistent read fixes
     * the snapshot every later consistent read in it is answered from. Run the search
     * inside the transaction and it becomes that first read — so a waiter that then
     * blocks on the anchor wakes up and reads the head from a snapshot taken BEFORE
     * it got the lock, i.e. the exact stale head the anchor exists to prevent. This
     * was measured, not reasoned about: with the search inside the transaction,
     * MariaDB went from 6 lost appends in 800 to the whole retry budget exhausted on
     * duplicate keys, hundreds of times. Outside, the first statement in the
     * transaction is the anchor's locking read (locking reads see the latest
     * committed row, snapshot or not), the head read after it establishes the
     * snapshot, and it sees the previous holder's commit.
     *
     * The cost is one extra indexed lookup per append on a key the append uses anyway.
     *
     * Two reads mean the anchor could vanish between them — only tail deletion does
     * that, which is tampering. Then the locking read finds nothing, the append falls
     * through to the unique key, and that is the same path as a genuinely empty chain.
     */
    private function anchorId(string $scope): ?string
    {
        $anchorId = $this->chain($scope)
            ->where('sequence', self::ANCHOR_SEQUENCE)
            ->value('id');

        return is_string($anchorId) ? $anchorId : null;
    }

    /**
     * Take the chain's serialisation lock: an exact primary-key match, so a record
     * lock and never a gap lock.
     *
     * sqlite compiles no lock clause; its writes serialise on the database anyway.
     */
    private function lockAnchor(string $anchorId): void
    {
        AuditEntry::query()
            ->withoutGlobalScope(EnvironmentScope::class)
            ->whereKey($anchorId)
            ->lockForUpdate()
            ->value('id');
    }

    public function headSequence(?string $organizationId = null): int
    {
        $head = $this->chain($this->scopeFor($organizationId))->max('sequence');

        return is_numeric($head) ? (int) $head : 0;
    }

    public function verifyChain(?string $organizationId = null, int $fromSequence = 1, ?int $toSequence = null): ChainVerification
    {
        $scope = $this->scopeFor($organizationId);
        $from = max(1, $fromSequence);

        $query = $this->chain($scope)
            ->where('sequence', '>=', $from)
            ->orderBy('sequence');

        if ($toSequence !== null) {
            $query->where('sequence', '<=', $toSequence);
        }

        $entries = $query->get();

        $expectedSequence = $from;
        $prevHash = self::GENESIS_HASH;

        if ($from > 1) {
            $before = $this->entryAt($scope, $from - 1);
            $prevHash = $before === null ? self::GENESIS_HASH : $before->hash;
        }

        foreach ($entries as $entry) {
            if ($entry->sequence !== $expectedSequence) {
                return ChainVerification::broken($entry->sequence, 'sequence gap or reordering');
            }

            if (! hash_equals($prevHash, $entry->prev_hash)) {
                return ChainVerification::broken($entry->sequence, 'prev-hash linkage mismatch');
            }

            if (! hash_equals($entry->hash, $this->computeHash($entry, $entry->prev_hash))) {
                return ChainVerification::broken($entry->sequence, 'content hash mismatch (tampered)');
            }

            $prevHash = $entry->hash;
            $expectedSequence++;
        }

        // Per-row/link integrity holds for the rows present — but that alone
        // can't detect entries deleted off the tail (or a wiped scope). Cross-
        // check the last signed checkpoint: the entry it anchored must still be
        // present with the same hash.
        $anchorBreak = $this->verifyCheckpointAnchor($scope);

        if ($anchorBreak !== null) {
            return $anchorBreak;
        }

        return ChainVerification::valid($entries->count());
    }

    /**
     * Detect deletion/truncation at or below the last checkpoint by re-verifying
     * its signature and confirming the anchored entry is unchanged. Returns a
     * broken verification if violated, or null if there is nothing to contradict.
     */
    private function verifyCheckpointAnchor(string $scope): ?ChainVerification
    {
        $checkpoint = AuditCheckpoint::query()
            ->withoutGlobalScope(EnvironmentScope::class)
            ->where('environment_id', $this->environmentKey())
            ->where('scope', $scope)
            ->orderByDesc('up_to_sequence')
            ->first();

        if ($checkpoint === null) {
            return null;
        }

        try {
            $claims = $this->signer->verify($checkpoint->signature, [SigningAlg::RS256, SigningAlg::ES256]);
        } catch (Throwable) {
            return ChainVerification::broken($checkpoint->up_to_sequence, 'checkpoint signature failed to verify');
        }

        $rootHash = $claims->get('root_hash');
        $upToSequence = $claims->get('up_to_sequence');

        if ($claims->get('scope') !== $scope
            || ! (is_int($upToSequence) || is_float($upToSequence))
            || (int) $upToSequence !== $checkpoint->up_to_sequence
            || ! is_string($rootHash)
            || ! hash_equals($rootHash, $checkpoint->root_hash)) {
            return ChainVerification::broken($checkpoint->up_to_sequence, 'checkpoint payload does not match its signature');
        }

        $anchor = $this->entryAt($scope, $checkpoint->up_to_sequence);

        if ($anchor === null || ! hash_equals($checkpoint->root_hash, $anchor->hash)) {
            return ChainVerification::broken($checkpoint->up_to_sequence, 'entries at or below the last checkpoint were removed or altered');
        }

        return null;
    }

    public function checkpoint(?string $organizationId = null): AuditCheckpoint
    {
        $scope = $this->scopeFor($organizationId);

        $head = $this->headEntry($scope, lock: false);

        if ($head === null) {
            throw CannotCheckpointEmptyScope::make($scope);
        }

        $signature = $this->signer->sign([
            'typ' => 'cbox-id.audit.checkpoint',
            'scope' => $scope,
            'up_to_sequence' => $head->sequence,
            'root_hash' => $head->hash,
            'iat' => now()->getTimestamp(),
        ]);

        $checkpoint = new AuditCheckpoint;
        $checkpoint->environment_id = $this->environmentKey();
        $checkpoint->fill([
            'scope' => $scope,
            'organization_id' => $organizationId,
            'up_to_sequence' => $head->sequence,
            'root_hash' => $head->hash,
            'signature' => $signature,
        ]);
        $checkpoint->save();

        return $checkpoint;
    }

    private function headEntry(string $scope, bool $lock): ?AuditEntry
    {
        $query = $this->chain($scope)->orderByDesc('sequence');

        if ($lock) {
            $query->lockForUpdate();
        }

        return $query->first();
    }

    private function entryAt(string $scope, int $sequence): ?AuditEntry
    {
        return $this->chain($scope)
            ->where('sequence', $sequence)
            ->first();
    }

    private function scopeFor(?string $organizationId): string
    {
        return $organizationId ?? self::SYSTEM_SCOPE;
    }

    private function computeHash(AuditEntry $entry, string $prevHash): string
    {
        return hash('sha256', $this->canonicalPayload($entry).$prevHash);
    }

    private function canonicalPayload(AuditEntry $entry): string
    {
        $payload = [
            'sequence' => $entry->sequence,
            // The chain is defined per (environment, scope), so the environment must be
            // INSIDE the hash — otherwise a row can be moved between environments with a
            // plain UPDATE and verifyChain() still reports it intact.
            'environment_id' => $entry->environment_id,
            'scope' => $entry->scope,
            'organization_id' => $entry->organization_id,
            'actor_type' => $entry->actor_type->value,
            'actor_id' => $entry->actor_id,
            'action' => $entry->action,
            'target_type' => $entry->target_type,
            'target_id' => $entry->target_id,
            'context' => $this->canonicalize($entry->context),
            'ip' => $entry->ip,
            'recorded_at' => $entry->recorded_at?->getTimestamp(),
        ];

        return json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Deterministic, recursively key-sorted structure so the hash is stable.
     *
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    private function canonicalize(array $data): array
    {
        ksort($data);

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->canonicalize($value);
            }
        }

        return $data;
    }
}
