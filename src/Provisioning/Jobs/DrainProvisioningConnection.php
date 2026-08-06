<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Jobs;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\Id\Provisioning\Contracts\ProvisioningService;
use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

/**
 * Drains ONE connection's provisioning outbox — the piece that makes
 * environment-owned models and asynchronous delivery coexist.
 *
 * The problem: the outbox models are hard-scoped to an environment, but a queue
 * worker runs with NO ambient environment, so a naive drain would hit
 * deny-by-default (`1 = 0`) and deliver nothing. The fix is an explicit
 * reconstruction, identical to the audit-streaming pump:
 *
 *   1. {@see EnvironmentContext::withoutScope()} — a provisioning-only system read
 *      that crosses the boundary just far enough to learn WHICH environment the
 *      connection belongs to (its `environment_id`), reading a single id.
 *   2. {@see EnvironmentContext::runAs()} — re-enters that exact environment, so
 *      the hard scope now MATCHES it.
 *   3. Inside `runAs`, {@see ProvisioningService::drainConnection()} loads and
 *      delivers ONLY this environment's operations — structurally unable to touch
 *      another environment's rows.
 *
 * {@see ShouldBeUnique} keyed by the connection id: at most one drain per
 * connection at a time, so the per-minute scheduler cannot start a second run
 * that re-claims the same still-pending operations and double-provisions.
 */
class DrainProvisioningConnection implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    /** The unique-lock ceiling — longer than a full drain, so a crashed worker cannot wedge a connection. */
    public int $uniqueFor = 900;

    public function __construct(public readonly string $connectionId) {}

    public function uniqueId(): string
    {
        return $this->connectionId;
    }

    public function handle(EnvironmentContext $context, ProvisioningService $provisioning): void
    {
        // System read across the boundary: learn the connection's environment
        // without trusting an ambient one (a worker has none).
        $environmentId = $context->withoutScope(
            fn (): mixed => ProvisioningConnection::query()->whereKey($this->connectionId)->value('environment_id'),
        );

        if (! is_string($environmentId) || $environmentId === '') {
            return;
        }

        // Re-enter that environment so the hard scope matches it, then drain.
        $context->runAs(GenericEnvironment::of($environmentId), function () use ($provisioning): void {
            $provisioning->drainConnection($this->connectionId);
        });
    }
}
