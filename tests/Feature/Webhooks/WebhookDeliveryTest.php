<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Enums\DeliveryStatus;
use Cbox\Id\Webhooks\Models\WebhookDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

// These tests target delivery, not the SSRF guard, and use unresolvable .test
// hosts — disable URL verification here (the guard has its own test).
beforeEach(fn () => config(['cbox-id.webhooks.verify_url' => false]));

it('registers an endpoint and reveals the secret exactly once', function (): void {
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['organization.created']);

    expect($registered->secret)->toHaveLength(64)
        ->and($registered->endpoint->url)->toBe('https://hook.test/x')
        ->and($registered->endpoint->secret_encrypted)->not->toBe($registered->secret);
});

it('delivers an HMAC-signed request to matching endpoints', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['organization.created']);

    app(WebhookDispatcher::class)->dispatch('organization.created', ['id' => 'org_a'], 'org_a');

    Http::assertSent(function (Request $request) use ($registered): bool {
        // Signature covers `timestamp.body` (Stripe-style, replay-resistant).
        $timestamp = $request->header('X-Cbox-Timestamp')[0];
        $expected = 't='.$timestamp.',v1='.hash_hmac('sha256', $timestamp.'.'.$request->body(), $registered->secret);

        return $request->url() === 'https://hook.test/x'
            && $request->header('X-Cbox-Signature')[0] === $expected;
    });

    expect(WebhookDelivery::query()->where('status', DeliveryStatus::Delivered->value)->count())->toBe(1);
});

it('does not deliver to endpoints not subscribed to the event', function (): void {
    Http::fake();
    $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);

    app(WebhookDispatcher::class)->dispatch('organization.created', [], 'org_a');

    Http::assertNothingSent();
});

it('delivers platform-wide endpoints for org-scoped events', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $this->registerWebhook(null, 'https://global.test', ['x.y']);

    app(WebhookDispatcher::class)->dispatch('x.y', [], 'org_a');

    Http::assertSentCount(1);
});

it('records a failure, schedules a retry, and succeeds on retry', function (): void {
    Http::fake(['*' => Http::sequence()->push('', 500)->push('', 200)]);
    $this->registerWebhook('org_a', 'https://hook.test/x', ['e']);

    app(WebhookDispatcher::class)->dispatch('e', [], 'org_a');

    $delivery = WebhookDelivery::query()->firstOrFail();
    expect($delivery->status)->toBe(DeliveryStatus::Failed)
        ->and($delivery->next_retry_at)->not->toBeNull();

    $delivery->update(['next_retry_at' => now()->subMinute()]);

    expect(app(WebhookDispatcher::class)->retryPending())->toBe(1)
        ->and(WebhookDelivery::query()->firstOrFail()->status)->toBe(DeliveryStatus::Delivered);
});

it('dead-letters a delivery after the retry cap and never retries it again', function (): void {
    config(['cbox-id.webhooks.max_attempts' => 2]);
    Http::fake(['*' => Http::response('', 500)]);
    $this->registerWebhook('org_a', 'https://hook.test/x', ['e']);

    app(WebhookDispatcher::class)->dispatch('e', [], 'org_a');
    $delivery = WebhookDelivery::query()->firstOrFail();
    expect($delivery->status)->toBe(DeliveryStatus::Failed)->and($delivery->attempt)->toBe(1);

    // Second (final) attempt hits the cap → dead-lettered, no further retry window.
    $delivery->update(['next_retry_at' => now()->subMinute()]);
    app(WebhookDispatcher::class)->retryPending();

    $delivery->refresh();
    expect($delivery->status)->toBe(DeliveryStatus::Exhausted)
        ->and($delivery->attempt)->toBe(2)
        ->and($delivery->next_retry_at)->toBeNull();

    // Exhausted deliveries are excluded from the retry sweep.
    expect(app(WebhookDispatcher::class)->retryPending())->toBe(0);
});

it('refuses delivery to an endpoint that fails the SSRF guard', function (): void {
    Http::fake();
    // Register with the guard off (file-wide beforeEach), then enable it for the
    // delivery: blocked.test resolves to a non-public address, so the guarded
    // send is refused — nothing goes out and the delivery is retried.
    $this->registerWebhook('org_a', 'https://blocked.test/x', ['e']);
    config(['cbox-id.webhooks.verify_url' => true]);

    app(WebhookDispatcher::class)->dispatch('e', [], 'org_a');

    Http::assertNothingSent();
    expect(WebhookDelivery::query()->firstOrFail()->status)->toBe(DeliveryStatus::Failed);
});

it('fans a delivered domain event out to webhooks end-to-end', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $this->registerWebhook('org_a', 'https://hook.test/x', ['thing.happened']);

    app(EventBus::class)->emit(new DomainEvent('thing.happened', ['n' => 1], 'org_a'));
    app(EventBus::class)->flushPending();

    Http::assertSentCount(1);
});

it('folds the event organization id into the delivered webhook payload', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $this->registerWebhook('org_a', 'https://hook.test/x', ['organization.member_added']);

    // Emitting enqueues on the outbox; flushing relays it as EventDelivered, which
    // the webhook layer fans out — injecting the org so a receiver (e.g. billing)
    // knows the tenant without a separate lookup.
    app(EventBus::class)->emit(new DomainEvent('organization.member_added', ['user_id' => 'user_1'], 'org_a'));
    app(EventBus::class)->flushPending();

    Http::assertSent(function (Request $request): bool {
        $body = json_decode($request->body(), true);

        return is_array($body)
            && ($body['data']['user_id'] ?? null) === 'user_1'
            && ($body['data']['organization_id'] ?? null) === 'org_a';
    });
});
