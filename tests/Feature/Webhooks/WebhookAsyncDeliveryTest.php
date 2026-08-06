<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Enums\DeliveryStatus;
use Cbox\Id\Webhooks\Enums\EndpointStatus;
use Cbox\Id\Webhooks\Jobs\DeliverWebhook;
use Cbox\Id\Webhooks\Models\WebhookDelivery;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Cbox\Id\Webhooks\Support\EndpointCircuitBreaker;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;

uses(RefreshDatabase::class);

// Delivery, not the SSRF guard — unresolvable .test hosts, guard off (it has its
// own test).
beforeEach(fn () => config(['cbox-id.webhooks.verify_url' => false]));

it('queues deliveries from the relay instead of sending them inline', function (): void {
    Queue::fake();
    Http::fake();
    $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);

    app(EventBus::class)->emit(new DomainEvent('user.created', ['n' => 1], 'org_a'));
    app(EventBus::class)->flushPending();

    // The relay thread does the bookkeeping and NOTHING else: the row is durable,
    // the job is queued, and no socket was opened on the scheduler process.
    Http::assertNothingSent();
    Queue::assertPushed(DeliverWebhook::class, 1);

    $delivery = WebhookDelivery::query()->firstOrFail();
    expect($delivery->status)->toBe(DeliveryStatus::Pending)
        ->and($delivery->attempt)->toBe(0);

    Queue::assertPushed(
        DeliverWebhook::class,
        fn (DeliverWebhook $job): bool => $job->deliveryId === $delivery->id,
    );
});

it('does not let a blackholing endpoint in one org delay another org\'s delivery', function (): void {
    Queue::fake();

    // org_a's receiver is a blackhole: any send to it would burn the full Guzzle
    // timeout. org_b's is healthy.
    Http::fake([
        'blackhole.test/*' => fn () => throw new ConnectionException('cURL error 28: Operation timed out'),
        '*' => Http::response('', 200),
    ]);

    $this->registerWebhook('org_a', 'https://blackhole.test/hook', ['user.created']);
    $registeredB = $this->registerWebhook('org_b', 'https://healthy.test/hook', ['user.created']);

    app(EventBus::class)->emit(new DomainEvent('user.created', ['n' => 1], 'org_a'));
    app(EventBus::class)->emit(new DomainEvent('user.created', ['n' => 2], 'org_b'));
    expect(app(EventBus::class)->flushPending())->toBe(2);

    // Both events left the relay; neither tenant waited on the other, because the
    // relay never touched the network. Ordering is irrelevant — the jobs are
    // independent units of work, which is the whole point.
    Http::assertNothingSent();
    Queue::assertPushed(DeliverWebhook::class, 2);

    // And org_b's delivery completes on its own, entirely unaffected by org_a's
    // dead endpoint — run just that job.
    $deliveryB = WebhookDelivery::query()
        ->where('endpoint_id', $registeredB->endpoint->id)
        ->firstOrFail();

    app(WebhookDispatcher::class)->deliver($deliveryB->id);

    expect($deliveryB->refresh()->status)->toBe(DeliveryStatus::Delivered);
    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://healthy.test/hook');
    Http::assertSentCount(1);

    // org_a's delivery is still queued and still Pending — parked, not lost.
    expect(WebhookDelivery::query()->where('status', DeliveryStatus::Pending->value)->count())->toBe(1);
});

it('re-enqueues due retries in one batched pass rather than sending them serially', function (): void {
    Http::fake(['*' => Http::response('', 500)]);
    $this->registerWebhook('org_a', 'https://hook.test/a', ['user.created']);
    $this->registerWebhook('org_a', 'https://hook.test/b', ['user.created']);

    // First round runs inline (sync queue) and fails both.
    app(WebhookDispatcher::class)->dispatch('user.created', [], 'org_a');
    WebhookDelivery::query()->update(['next_retry_at' => now()->subMinute()]);

    Queue::fake();

    // A CONSTANT number of statements touch webhook_endpoints regardless of how many
    // deliveries are due — the orphan sweep and the existence predicate on the selection
    // — where the old shape issued one WebhookEndpoint query per delivery.
    $endpointQueries = 0;
    DB::listen(function ($query) use (&$endpointQueries): void {
        if (str_contains($query->sql, 'webhook_endpoints')) {
            $endpointQueries++;
        }
    });

    expect(app(WebhookDispatcher::class)->retryPending())->toBe(2);

    expect($endpointQueries)->toBe(2);
    Queue::assertPushed(DeliverWebhook::class, 2);
    Http::assertSentCount(2); // still only the two original inline attempts
});

it('trips an endpoint after N consecutive failures and skips it until the cooldown elapses', function (): void {
    config([
        'cbox-id.webhooks.circuit_breaker.failure_threshold' => 2,
        'cbox-id.webhooks.circuit_breaker.cooldown_seconds' => 600,
    ]);
    // Two failures, then a healthy response. Only THREE responses are staged: if the
    // breaker ever let the parked third event through, the sequence would run dry.
    Http::fake(['*' => Http::sequence()->push('', 500)->push('', 500)->push('', 200)]);

    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);

    // Two failing deliveries reach the threshold (sync queue → the jobs run inline).
    app(WebhookDispatcher::class)->dispatch('user.created', ['n' => 1], 'org_a');
    app(WebhookDispatcher::class)->dispatch('user.created', ['n' => 2], 'org_a');

    Http::assertSentCount(2);

    $endpoint = WebhookEndpoint::query()->whereKey($registered->endpoint->id)->firstOrFail();
    expect($endpoint->consecutive_failures)->toBe(2)
        ->and($endpoint->circuit_opened_at)->not->toBeNull();

    // The breaker is open, so the THIRD event is recorded and parked without a
    // single socket being opened — the endpoint now costs one timeout per cooldown
    // window rather than one per event.
    app(WebhookDispatcher::class)->dispatch('user.created', ['n' => 3], 'org_a');

    Http::assertSentCount(2);

    $third = WebhookDelivery::query()->orderByDesc('sequence')->firstOrFail();
    expect($third->status)->toBe(DeliveryStatus::Failed)
        ->and($third->attempt)->toBe(0)  // the trip is the endpoint's fault, not this delivery's
        ->and($third->next_retry_at?->timestamp)
        ->toBe(app(EndpointCircuitBreaker::class)->closesAt($endpoint)?->timestamp);

    // The trip is visible without any knowledge of columns or config.
    $health = app(EndpointCircuitBreaker::class)->health($endpoint);
    expect($health->isTripped())->toBeTrue()
        ->and($health->lastError)->toBe('HTTP 500');

    // ...and it is NOT a pause: `status` is the operator's intent and stays untouched.
    expect($endpoint->status)->toBe(EndpointStatus::Active);

    // Past the cooldown the breaker admits a probe again, and a healthy response
    // closes it.
    $this->travel(601)->seconds();

    app(WebhookDispatcher::class)->deliver($third->id);

    Http::assertSentCount(3);

    expect($third->refresh()->status)->toBe(DeliveryStatus::Delivered);

    $endpoint->refresh();
    expect($endpoint->consecutive_failures)->toBe(0)
        ->and($endpoint->circuit_opened_at)->toBeNull()
        ->and(app(EndpointCircuitBreaker::class)->health($endpoint)->isTripped())->toBeFalse();
});

it('rescues a delivery whose job was lost, so a queued row is never stranded', function (): void {
    config(['cbox-id.webhooks.stranded_after_seconds' => 900]);
    Queue::fake();
    Http::fake();
    $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);

    app(WebhookDispatcher::class)->dispatch('user.created', [], 'org_a');

    // The row is Pending and its job has (as far as the database can tell) vanished.
    // Fresh, it is left alone — a worker may simply not have reached it yet.
    expect(WebhookDelivery::query()->firstOrFail()->status)->toBe(DeliveryStatus::Pending)
        ->and(app(WebhookDispatcher::class)->retryPending())->toBe(0);

    // Past the stranded window the sweep re-enqueues it rather than losing the event.
    $this->travel(901)->seconds();

    expect(app(WebhookDispatcher::class)->retryPending())->toBe(1);
    Queue::assertPushed(DeliverWebhook::class, 2);
});

it('never re-sends a delivery that has already settled', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);

    app(WebhookDispatcher::class)->dispatch('user.created', [], 'org_a');
    $delivery = WebhookDelivery::query()->firstOrFail();
    expect($delivery->status)->toBe(DeliveryStatus::Delivered);

    // A duplicate job (a replayed queue message, a retried worker) must be inert.
    app(WebhookDispatcher::class)->deliver($delivery->id);

    Http::assertSentCount(1);
});

it('reconstructs the delivery\'s environment inside the job', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);
    app(WebhookDispatcher::class)->dispatch('user.created', [], 'org_a');

    $delivery = WebhookDelivery::query()->firstOrFail();
    $delivery->update(['status' => DeliveryStatus::Pending, 'delivered_at' => null]);

    // A worker carries NO ambient environment; the job must recover it from the row
    // or the hard environment scope would deny every read.
    app(EnvironmentContext::class)->set(null);

    app()->call([new DeliverWebhook($delivery->id), 'handle']);

    $this->actingAsEnvironment('env_test');

    expect(WebhookDelivery::query()->findOrFail($delivery->id)->status)->toBe(DeliveryStatus::Delivered);
});

/**
 * A delivery whose ENDPOINT has been deleted must reach a terminal status.
 *
 * Endpoint deletion does not cascade, and now that the send is asynchronous the row
 * outlives its job: deliver() found no endpoint and returned, leaving `Pending` forever.
 * Before today's async change this state could not exist — the send was inline, so a row
 * always settled in the same request.
 */
it('settles a delivery whose endpoint has been deleted instead of leaving it pending', function (): void {
    Queue::fake();
    Http::fake();
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);

    app(WebhookDispatcher::class)->dispatch('user.created', [], 'org_a');

    $delivery = WebhookDelivery::query()->firstOrFail();
    WebhookEndpoint::query()->whereKey($registered->endpoint->id)->delete();

    app(WebhookDispatcher::class)->deliver($delivery->id);

    expect($delivery->refresh()->status)->toBe(DeliveryStatus::Exhausted)
        ->and($delivery->next_retry_at)->toBeNull();
});

/**
 * ...and orphans must never starve the sweep.
 *
 * `retryPending()` is ordered by `created_at` ASCENDING and the orphans are the OLDEST
 * rows, so they sat permanently at the head of it. The old code skipped them inside the
 * loop — AFTER each had already consumed one of the `$limit` slots — so with `retry_limit`
 * orphans no legitimate failed delivery was ever re-enqueued again. The pruner could not
 * clear them either: it takes only Delivered/Exhausted.
 */
it('does not let orphaned deliveries consume the retry sweep\'s budget', function (): void {
    Http::fake(['*' => Http::response('', 500)]);

    $doomed = $this->registerWebhook('org_a', 'https://orphan.test/x', ['user.created']);

    // Three deliveries against an endpoint that is then deleted — the oldest rows.
    foreach ([1, 2, 3] as $n) {
        app(WebhookDispatcher::class)->dispatch('user.created', ['n' => $n], 'org_a');
    }

    WebhookEndpoint::query()->whereKey($doomed->endpoint->id)->delete();

    // A live endpoint with one genuinely failed delivery, created LAST.
    $this->travel(1)->seconds();
    $this->registerWebhook('org_b', 'https://hook.test/y', ['user.created']);
    app(WebhookDispatcher::class)->dispatch('user.created', ['n' => 4], 'org_b');

    WebhookDelivery::query()
        ->where('status', DeliveryStatus::Failed->value)
        ->update(['next_retry_at' => now()->subMinute()]);

    Queue::fake();

    // A budget of three: entirely consumed by the orphans under the old shape.
    expect(app(WebhookDispatcher::class)->retryPending(3))->toBe(1);

    Queue::assertPushed(DeliverWebhook::class, 1);

    // The orphans are settled, so the pruner can finally reach them.
    expect(WebhookDelivery::query()->where('endpoint_id', $doomed->endpoint->id)->get())
        ->each(fn ($delivery) => $delivery->status->toBe(DeliveryStatus::Exhausted));
});
