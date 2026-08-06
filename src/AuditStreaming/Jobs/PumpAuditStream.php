<?php

declare(strict_types=1);

namespace Cbox\Id\AuditStreaming\Jobs;

use Cbox\Id\AuditStreaming\Models\AuditStream;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\LaravelSiem\Jobs\PumpStreamDeliveries;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

/**
 * Delivers one environment-owned audit stream's outbox — the piece that makes
 * environment-owned models and asynchronous delivery coexist.
 *
 * The problem: the engine's delivery models are hard-scoped to an environment, but
 * a queue worker runs with NO ambient environment, so a naive pump would hit
 * deny-by-default (`1 = 0`) and deliver nothing. The fix is an explicit
 * reconstruction:
 *
 *   1. {@see EnvironmentContext::withoutScope()} — a provisioning-only system read
 *      that crosses the boundary just far enough to learn WHICH environment the
 *      stream belongs to (its `environment_id`). This is the only cross-environment
 *      step, and it reads a single id, nothing else.
 *   2. {@see EnvironmentContext::runAs()} — re-enters that exact environment, so
 *      the hard scope now MATCHES it.
 *   3. Inside `runAs`, {@see PumpStreamDeliveries::dispatchSync()} runs laravel-siem's
 *      real delivery synchronously (same process, same context singleton), so its
 *      env-owned AuditStream / AuditStreamDelivery queries load ONLY this
 *      environment's rows and are structurally unable to touch another's.
 *
 * {@see ShouldBeUnique} keyed by the stream id: at most one pump per stream at a
 * time, so the per-minute scheduler cannot start a second run while one is still
 * draining and re-ship the same still-`pending` rows.
 */
class PumpAuditStream implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    /**
     * The unique-lock ceiling — comfortably longer than a full drain, so a
     * crashed worker cannot wedge a stream's slot forever. Matches the inner
     * {@see PumpStreamDeliveries::$uniqueFor}.
     */
    public int $uniqueFor = 900;

    public function __construct(public readonly string $streamId) {}

    public function uniqueId(): string
    {
        return $this->streamId;
    }

    public function handle(EnvironmentContext $context): void
    {
        // System read across the boundary: learn the stream's environment WITHOUT
        // trusting an ambient one (a worker has none). If the stream vanished, do
        // nothing.
        $environmentId = $context->withoutScope(
            fn (): mixed => AuditStream::query()->whereKey($this->streamId)->value('environment_id'),
        );

        if (! is_string($environmentId) || $environmentId === '') {
            return;
        }

        // Re-enter that environment so the hard scope matches it, then run the real
        // delivery synchronously inside it. GenericEnvironment is sufficient: the
        // scope compares only the environment key.
        $context->runAs(GenericEnvironment::of($environmentId), function (): void {
            PumpStreamDeliveries::dispatchSync($this->streamId);
        });
    }
}
