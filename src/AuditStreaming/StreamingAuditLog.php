<?php

declare(strict_types=1);

namespace Cbox\Id\AuditStreaming;

use Cbox\Id\AuditStreaming\Contracts\SiemEventMapper;
use Cbox\Id\AuditStreaming\Models\AuditStream;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Models\AuditCheckpoint;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Audit\ValueObjects\ChainVerification;
use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Illuminate\Support\Facades\DB;

/**
 * A container decorator over the framework {@see AuditLog} that mirrors every
 * recorded entry OUT to the environment's configured SIEM streams, via the
 * transactional outbox in cboxdk/laravel-siem.
 *
 * Bound with `app->extend(AuditLog::class, ...)`, so it COMPOSES with any host
 * decorator (e.g. an impersonation-attribution wrapper): it wraps whatever inner
 * AuditLog already exists and is, in turn, wrappable. Because it decorates the
 * contract, a host stamping `context.impersonated_by` upstream flows through to
 * the SIEM automatically.
 *
 * Isolation is inherited, not re-implemented: it runs inside the record() call's
 * environment, so listing streams ({@see LogStreams::enabled()}, an env-owned
 * query) and writing outbox rows ({@see StreamDispatcher::dispatch()}, an env-owned
 * write) are both constrained to that environment by the hard environment scope.
 * An env-A entry can only ever match/write env-A streams.
 *
 * Atomicity: when at least one stream is configured, the inner record() AND the
 * outbox insert run in ONE database transaction (a savepoint when the caller is
 * already in one), so the audit entry and the intent-to-deliver commit together —
 * a rolled-back caller leaves neither the entry nor an orphan delivery
 * (transactional outbox → at-least-once). Only the cheap outbox insert is in-txn;
 * the actual network delivery is asynchronous and never rolls the caller back.
 *
 * Deny-by-default: with no stream configured in the environment, this is a no-op
 * over the inner record() — a single cheap `enabled` query and nothing more.
 */
class StreamingAuditLog implements AuditLog
{
    public function __construct(
        private readonly AuditLog $inner,
        private readonly StreamDispatcher $dispatcher,
        private readonly SiemEventMapper $mapper,
    ) {}

    public function record(AuditEvent $event): AuditEntry
    {
        // Env-scoped AND organization-scoped. The environment scope is inherited from the
        // model and bounds this to the current environment; the organization filter is
        // the one this used to be missing.
        //
        // Every enabled stream in the environment received every entry recorded anywhere
        // in it. That was right while only an operator could configure one — and the
        // console has since put log streaming on the ORGANIZATION plane, on the fair
        // argument that shipping an audit trail to a SIEM is a compliance obligation the
        // organization carries. Together they meant an administrator of organization A
        // registered an endpoint and received B and C's sign-ins, role changes and member
        // events: not a leak anyone had to work for, the feature working as built on a
        // plane that was never in its design.
        //
        // A stream with no organization is still the ENVIRONMENT's own and still receives
        // everything — that is what every stream was, and the operator's own compliance
        // shipping depends on it.
        /** @var list<AuditStream> $streams */
        $streams = AuditStream::query()
            ->where('enabled', true)
            ->deliverableFor($event->organizationId)
            ->get()
            ->all();

        // Deny-by-default: nothing configured for this environment ⇒ no overhead
        // beyond the inner record() (which manages its own transaction).
        if ($streams === []) {
            return $this->inner->record($event);
        }

        // Atomic transactional outbox: the entry and its delivery rows commit
        // together (savepoint if the caller already opened a transaction).
        return DB::transaction(function () use ($event, $streams): AuditEntry {
            $entry = $this->inner->record($event);

            $this->dispatcher->dispatch($this->mapper->toSiemEvent($entry), $streams);

            return $entry;
        });
    }

    public function verifyChain(?string $organizationId = null, int $fromSequence = 1, ?int $toSequence = null): ChainVerification
    {
        return $this->inner->verifyChain($organizationId, $fromSequence, $toSequence);
    }

    public function headSequence(?string $organizationId = null): int
    {
        return $this->inner->headSequence($organizationId);
    }

    public function checkpoint(?string $organizationId = null): AuditCheckpoint
    {
        return $this->inner->checkpoint($organizationId);
    }
}
