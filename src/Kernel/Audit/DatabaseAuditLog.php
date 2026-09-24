<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit;

use Cbox\AuditChain\Contracts\CheckpointAnchor;
use Cbox\AuditChain\DatabaseAuditChain;
use Cbox\AuditChain\Exceptions\CannotAppendToChain;
use Cbox\AuditChain\Exceptions\CannotCheckpointEmptyChain;
use Cbox\AuditChain\Exceptions\InvalidChainModel;
use Cbox\AuditChain\ValueObjects\ChainActor;
use Cbox\AuditChain\ValueObjects\ChainEvent;
use Cbox\AuditChain\ValueObjects\ChainKey;
use Cbox\Id\Kernel\Audit\Chain\AuditStorage;
use Cbox\Id\Kernel\Audit\Chain\CboxIdEntryCodec;
use Cbox\Id\Kernel\Audit\Chain\TokenCheckpointSigner;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Exceptions\CannotAppendToAuditChain;
use Cbox\Id\Kernel\Audit\Exceptions\CannotCheckpointEmptyScope;
use Cbox\Id\Kernel\Audit\Models\AuditCheckpoint;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Audit\ValueObjects\ChainVerification;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Closure;

/**
 * The platform's audit trail: the {@see AuditLog} contract over cboxdk/laravel-audit-chain.
 *
 * The chain itself — the append path and its concurrency handling, verification, the
 * checkpoint cross-check — lives in the package's {@see DatabaseAuditChain}, extracted
 * from this class unchanged. What stays here is what makes it the PLATFORM's chain:
 *
 * - the addressing: a chain is (environment, scope), where the scope is an organization
 *   id or `__system__`, and the environment is resolved from context per call, with the
 *   `__platform__` sentinel outside any environment;
 * - the storage: `audit_logs` / `audit_checkpoints` through {@see AuditEntry} and
 *   {@see AuditCheckpoint}, with `organization_id` as a hashed extra column;
 * - the canonical form ({@see CboxIdEntryCodec}), byte-identical to every row already
 *   written;
 * - checkpoint signatures as Crypto-kernel JWTs ({@see TokenCheckpointSigner}).
 *
 * tests/Feature/Kernel/Audit/GoldenVectors holds all of it to rows the pre-extraction
 * implementation wrote: they still verify, and replaying their inputs reproduces them.
 */
class DatabaseAuditLog implements AuditLog
{
    /**
     * The scope of entries that belong to no organization — the environment's own
     * trail. Public because a chain is addressed by (environment, scope) from outside
     * too: {@see Checkpointer} enumerates the stored scopes and has to map this one back
     * to the `null` organization the contract speaks in.
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

    private readonly DatabaseAuditChain $chain;

    /**
     * @param  CheckpointAnchor|null  $anchor  where signed checkpoints are exported; the
     *                                         container's binding when omitted (the
     *                                         package default exports nothing)
     */
    public function __construct(
        private readonly TokenSigner $signer,
        ?CheckpointAnchor $anchor = null,
    ) {
        $this->chain = new DatabaseAuditChain(
            AuditStorage::models(),
            new CboxIdEntryCodec,
            new TokenCheckpointSigner($this->signer),
            $anchor ?? app(CheckpointAnchor::class),
        );
    }

    /**
     * Append one entry to the (environment, scope) chain.
     *
     * The append is the package's, unchanged from the implementation that lived here:
     * appenders serialise on the chain's anchor row (sequence 1), found with a plain
     * read OUTSIDE the transaction and locked by primary key, and a duplicate key or a
     * serialisation failure re-reads the head and retries on one jittered ladder of
     * eight attempts. The reasoning, and what it was measured against, is written out
     * on {@see DatabaseAuditChain::record()} and in the package's
     * docs/core-concepts/concurrency.md.
     *
     * @throws CannotAppendToAuditChain when every attempt lost the race
     */
    public function record(AuditEvent $event): AuditEntry
    {
        $key = $this->keyFor($event->organizationId);

        try {
            $entry = $this->chain->record($key, new ChainEvent(
                action: $event->action,
                actor: new ChainActor($event->actorType->value, $event->actorId),
                targetType: $event->targetType,
                targetId: $event->targetId,
                context: $event->context,
                ip: $event->ip,
                // The column this platform adds to every entry, and hashes.
                columns: ['organization_id' => $event->organizationId],
            ));
        } catch (CannotAppendToChain $exhausted) {
            // The platform's own exception (a subclass of the package's), with the
            // message and previous exception it has always carried.
            throw CannotAppendToAuditChain::afterAttempts($key->scope, $exhausted->attempts, $exhausted->getPrevious() ?? $exhausted);
        }

        if (! $entry instanceof AuditEntry) {
            throw InvalidChainModel::unexpectedInstance(AuditEntry::class, $entry::class);
        }

        return $entry;
    }

    public function headSequence(?string $organizationId = null): int
    {
        return $this->chain->head($this->keyFor($organizationId));
    }

    public function verifyChain(?string $organizationId = null, int $fromSequence = 1, ?int $toSequence = null): ChainVerification
    {
        $result = $this->chain->verify($this->keyFor($organizationId), $fromSequence, $toSequence);

        if ($result->valid) {
            return ChainVerification::valid($result->verifiedCount);
        }

        return ChainVerification::broken($result->brokenAtSequence ?? 0, $result->reason ?? 'verification failed');
    }

    public function checkpoint(?string $organizationId = null): AuditCheckpoint
    {
        $key = $this->keyFor($organizationId);

        try {
            $checkpoint = $this->inChainEnvironment(fn () => $this->chain->checkpoint($key));
        } catch (CannotCheckpointEmptyChain) {
            throw CannotCheckpointEmptyScope::make($key->scope);
        }

        if (! $checkpoint instanceof AuditCheckpoint) {
            throw InvalidChainModel::unexpectedInstance(AuditCheckpoint::class, $checkpoint::class);
        }

        return $checkpoint;
    }

    /**
     * Run a signing step as the chain's own environment.
     *
     * Signing keys are environment-owned. Inside an environment that is simply the
     * current one. OUTSIDE any environment — the platform plane, whose chain is the
     * `__platform__` partition — there is no key to find, and none can be generated
     * (a key needs an environment to belong to), so signing threw. The platform chain is
     * therefore signed as the `__platform__` environment: the same environment, and so
     * the same key, the checkpoint pass has always entered to sign it.
     *
     * An environment already in context is left exactly as it is.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $callback
     * @return TResult
     */
    private function inChainEnvironment(Closure $callback): mixed
    {
        $context = app(EnvironmentContext::class);

        if ($context->current() !== null) {
            return $callback();
        }

        return $context->runAs(GenericEnvironment::of(self::PLATFORM_ENVIRONMENT), $callback);
    }

    /**
     * The chain an organization's entries belong to, in the CURRENT environment.
     */
    private function keyFor(?string $organizationId): ChainKey
    {
        return new ChainKey($this->environmentKey(), $organizationId ?? self::SYSTEM_SCOPE);
    }

    /**
     * The chain's environment dimension, resolved EXPLICITLY and LAZILY.
     *
     * Never taken from the global scope: a chain head read through an ambient scope
     * returns null when no environment is set (EnvironmentScope emits `1 = 0`), which
     * restarts the chain on every write instead of extending it. (The package's chain
     * queries drop global scopes and state the environment themselves.)
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
}
