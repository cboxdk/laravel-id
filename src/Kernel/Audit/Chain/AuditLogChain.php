<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Chain;

use Cbox\AuditChain\Contracts\AuditChain;
use Cbox\AuditChain\Enums\ChainBreak;
use Cbox\AuditChain\Models\ChainCheckpoint;
use Cbox\AuditChain\Models\ChainEntry;
use Cbox\AuditChain\ValueObjects\ChainEvent;
use Cbox\AuditChain\ValueObjects\ChainKey;
use Cbox\AuditChain\ValueObjects\ChainVerification as PackageVerification;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\DatabaseAuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Closure;

/**
 * The package's {@see AuditChain} contract, answered by the platform's {@see AuditLog}.
 *
 * The AuditLog stack — the database log plus every decorator a host or module wraps
 * around it (SIEM streaming, impersonation attribution) — is the platform's one way into
 * the trail. This adapter lets code written against the package's contract (the
 * `audit-chain:*` commands, the package's Checkpointer and ChainVerifier) use that same
 * stack instead of a second, undecorated path to the same tables.
 *
 * A {@see ChainKey} maps onto the platform's addressing: the partition is an
 * environment key (or `__platform__`), the scope an organization id (or `__system__`).
 * Each call runs inside the chain's own environment, so it is correct from any context.
 *
 * The AuditLog is resolved per call unless one is given, so a test that fakes it (or a
 * host that decorates it late) is seen.
 */
class AuditLogChain implements AuditChain
{
    public function __construct(
        private readonly ?AuditLog $log = null,
        private readonly EnvironmentChainContext $context = new EnvironmentChainContext,
    ) {}

    public function record(ChainKey $key, ChainEvent $event): ChainEntry
    {
        return $this->in($key, fn (): ChainEntry => $this->log()->record(new AuditEvent(
            action: $event->action,
            actorType: ActorType::from($event->actor->type),
            actorId: $event->actor->id,
            organizationId: $this->organizationOf($key),
            targetType: $event->targetType,
            targetId: $event->targetId,
            context: $event->context,
            ip: $event->ip,
        )));
    }

    public function verify(ChainKey $key, int $fromSequence = 1, ?int $toSequence = null): PackageVerification
    {
        $verification = $this->in($key, fn () => $this->log()->verifyChain($this->organizationOf($key), $fromSequence, $toSequence));

        if ($verification->valid) {
            return PackageVerification::valid($verification->verifiedCount);
        }

        return new PackageVerification(
            false,
            $verification->verifiedCount,
            $verification->brokenAtSequence,
            $verification->reason === null ? null : ChainBreak::tryFrom($verification->reason),
        );
    }

    public function head(ChainKey $key): int
    {
        return $this->in($key, fn (): int => $this->log()->headSequence($this->organizationOf($key)));
    }

    public function checkpoint(ChainKey $key): ChainCheckpoint
    {
        return $this->in($key, fn (): ChainCheckpoint => $this->log()->checkpoint($this->organizationOf($key)));
    }

    private function organizationOf(ChainKey $key): ?string
    {
        return $key->scope === DatabaseAuditLog::SYSTEM_SCOPE ? null : $key->scope;
    }

    private function log(): AuditLog
    {
        return $this->log ?? app(AuditLog::class);
    }

    /**
     * @template TResult
     *
     * @param  Closure(): TResult  $callback
     * @return TResult
     */
    private function in(ChainKey $key, Closure $callback): mixed
    {
        return $this->context->run($key, $callback);
    }
}
