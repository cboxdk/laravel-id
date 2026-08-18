<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Enums\DeliveryStatus;
use Cbox\Id\Webhooks\Jobs\DeliverWebhook;
use Cbox\Id\Webhooks\Models\WebhookDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/*
 * Pest ignores a file-level `@group` docblock — membership comes only from a `uses()` or
 * a per-test `->group()`. So the 17 files that declared the group this way contributed
 * ZERO tests to `--group=isolation`, including the environment-isolation proof itself,
 * while docs/core-concepts/environments.md tells operators to run exactly that command
 * as the evidence. A selector that silently omits its own load-bearing file is worse than
 * no selector.
 */
uses()->group('isolation');

// This test is about environment isolation, not the SSRF guard (covered
// elsewhere); keep registration offline-deterministic.
beforeEach(fn () => config(['cbox-id.webhooks.verify_url' => false]));

/**
 * @group isolation
 *
 * Webhook endpoints — including platform-wide (null-org) ones — are
 * environment-owned, so a subscriber registered in one environment never
 * receives another environment's events.
 */
it('never matches a platform-wide endpoint across environments', function (): void {
    // A platform-wide (org = null) endpoint in env_a.
    $this->runAsEnvironment('env_a', fn () => app(WebhookRegistry::class)
        ->registerForEnvironment('https://a.example.com/hook', ['user.created']));

    // From env_b, the same platform-wide event must match nothing.
    $matchInB = $this->runAsEnvironment('env_b', fn () => app(WebhookRegistry::class)
        ->matching(null, 'user.created'));
    expect($matchInB)->toHaveCount(0);

    // From env_a it still matches, proving the endpoint exists (just isolated).
    $matchInA = $this->runAsEnvironment('env_a', fn () => app(WebhookRegistry::class)
        ->matching(null, 'user.created'));
    expect($matchInA)->toHaveCount(1);
});

it('flushes a pending event in ITS OWN environment, not the ambient one (R7a)', function (): void {
    Http::fake(['*' => Http::response('', 200)]);

    // A real environment row (forKey resolves it) with an endpoint scoped to it.
    $envA = Environment::create(['name' => 'A', 'slug' => 'flush-a', 'is_default' => false]);
    $this->runAsEnvironment($envA->id, fn () => app(WebhookRegistry::class)
        ->registerForEnvironment('https://a.example.com/hook', ['user.created']));

    // Emit the event inside env A (stamps environment_id = envA), but FLUSH from a
    // different ambient context — delivery must still fire for env A's endpoint.
    $this->runAsEnvironment($envA->id, fn () => app(EventBus::class)->emit(new DomainEvent('user.created', ['n' => 1])));
    $this->runAsEnvironment('unrelated-env', fn () => app(EventBus::class)->flushPending());

    Http::assertSentCount(1);
});

/**
 * THE SWEEP MUST SPAN EVERY ENVIRONMENT, because the process that runs it is in none.
 *
 * `retryPending()` is called from the scheduler, and a scheduler process has no ambient
 * environment — `EnvironmentContext` is a `scoped` binding that starts null and is only
 * populated by an HTTP middleware or by a job re-entering its own environment. Both
 * models here are environment-owned with a deny-by-default scope, so a select inside that
 * null context compiled to `WHERE 1 = 0` and the sweep returned zero. Silently, and
 * forever: nothing throws, nothing logs, the count is just always 0.
 *
 * What it cost is not "retries were slow". A failed delivery was never retried at all; a
 * `Pending` row whose job was lost was never rescued, so the module's "durable before
 * enqueued" promise was inert in production; and orphans were never terminalised, so the
 * pruner — which takes only Delivered and Exhausted — could never remove them and the
 * table grew without bound.
 *
 * EVERY EXISTING TEST PASSED, and that is the part worth keeping in mind: the suite pins
 * an environment before it runs anything, so `retryPending()` always had one. The only
 * way to see this is to call it the way the scheduler does — from nowhere — which is what
 * this does.
 */
it('sweeps deliveries from every environment, including from no environment at all', function (): void {
    $envA = Environment::query()->create(['name' => 'A', 'slug' => 'sweep-a', 'settings' => []]);
    $envB = Environment::query()->create(['name' => 'B', 'slug' => 'sweep-b', 'settings' => []]);

    foreach ([$envA, $envB] as $environment) {
        $this->runAsEnvironment($environment->id, function (): void {
            $endpoint = app(WebhookRegistry::class)
                ->registerForEnvironment('https://hooks.sweep.example/in', ['user.created'])
                ->endpoint;

            // A failure whose backoff window has already elapsed — due, on any sweep that
            // can see it.
            WebhookDelivery::query()->create([
                'endpoint_id' => $endpoint->id,
                'event_type' => 'user.created',
                'payload' => [],
                'status' => DeliveryStatus::Failed,
                'attempt' => 1,
                'next_retry_at' => now()->subMinute(),
            ]);
        });
    }

    Bus::fake();

    // FROM NOWHERE, and called EXACTLY as the scheduler calls it.
    //
    // The environment is cleared first rather than the call being wrapped: wrapping it
    // here would create the no-scope condition from outside and prove only that the
    // sweep works when somebody else already suspended scoping — which the scheduler
    // does not do. Clearing and then calling plainly is the production shape, and it is
    // the only form of this test that can go red.
    app(EnvironmentContext::class)->set(null);

    $swept = app(WebhookDispatcher::class)->retryPending();

    expect($swept)->toBe(2, 'the sweep did not reach both environments');

    Bus::assertDispatchedTimes(DeliverWebhook::class, 2);
})->group('isolation');
