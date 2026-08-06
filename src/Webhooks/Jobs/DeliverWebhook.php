<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Jobs;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\Id\Provisioning\Jobs\DrainProvisioningConnection;
use Cbox\Id\Provisioning\Listeners\ProvisionOnDomainEvent;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Models\WebhookDelivery;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

/**
 * Ships ONE webhook delivery over HTTP, off the delivering thread.
 *
 * This job exists because the fan-out used to run inline: a plain closure on
 * `EventDelivered` called the dispatcher, which looped every matching endpoint
 * SERIALLY and made a blocking `Http::connectTimeout(5)->timeout(10)` call per
 * endpoint — on the scheduler process, inside the relay's `withoutOverlapping()`
 * lock. Guzzle's `timeout` is TOTAL, so one blackholing receiver cost up to 10s
 * per attempt (a true blackhole trips the 5s connect timeout first): a 100-event
 * relay pass could take roughly 8–17 minutes, during which EVERY other tenant's
 * webhooks, usage metering and outbound SCIM sat behind it. One customer's dead
 * endpoint was every customer's outage.
 *
 * The listener now only persists rows and enqueues — the same rule
 * {@see ProvisionOnDomainEvent} has always
 * followed: never make a network call on the delivering thread.
 *
 * Environment reconstruction is the same three-step dance as
 * {@see DrainProvisioningConnection}: a queue worker
 * carries NO ambient environment, so the hard scope on the environment-owned
 * delivery/endpoint models would deny-by-default. Read the delivery's
 * `environment_id` with the scope suspended, then re-enter exactly that
 * environment to do the work.
 *
 * {@see ShouldBeUnique} keyed by the delivery id: the retry sweep runs every
 * minute and re-selects any Failed delivery whose backoff has elapsed, so
 * without the lock a backed-up queue would accumulate several jobs for the SAME
 * delivery and send it more than once.
 */
class DeliverWebhook implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    /**
     * Unique-lock ceiling. Deliberately the SAME window the retry sweep uses to
     * decide a Pending delivery is stranded: while the lock holds, a job for this
     * delivery is presumed alive and the sweep's re-enqueue is correctly suppressed;
     * the moment the delivery counts as stranded, the lock has expired and the sweep
     * can actually rescue it. A longer ceiling would wedge the rescue shut.
     */
    public int $uniqueFor;

    public function __construct(public readonly string $deliveryId)
    {
        $configured = config('cbox-id.webhooks.stranded_after_seconds', 900);

        $this->uniqueFor = max(1, is_numeric($configured) ? (int) $configured : 900);
    }

    public function uniqueId(): string
    {
        return $this->deliveryId;
    }

    public function handle(EnvironmentContext $context, WebhookDispatcher $dispatcher): void
    {
        // System read across the boundary: learn the delivery's environment
        // without trusting an ambient one (a worker has none).
        $environmentId = $context->withoutScope(
            fn (): mixed => WebhookDelivery::query()->whereKey($this->deliveryId)->value('environment_id'),
        );

        if (! is_string($environmentId) || $environmentId === '') {
            return;
        }

        $context->runAs(GenericEnvironment::of($environmentId), function () use ($dispatcher): void {
            $dispatcher->deliver($this->deliveryId);
        });
    }
}
