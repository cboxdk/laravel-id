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
        $expected = 'sha256='.hash_hmac('sha256', $request->body(), $registered->secret);

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

it('fans a delivered domain event out to webhooks end-to-end', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $this->registerWebhook('org_a', 'https://hook.test/x', ['thing.happened']);

    app(EventBus::class)->emit(new DomainEvent('thing.happened', ['n' => 1], 'org_a'));
    app(EventBus::class)->flushPending();

    Http::assertSentCount(1);
});
