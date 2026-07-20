<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

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
        ->register(null, 'https://a.example.com/hook', ['user.created']));

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
        ->register(null, 'https://a.example.com/hook', ['user.created']));

    // Emit the event inside env A (stamps environment_id = envA), but FLUSH from a
    // different ambient context — delivery must still fire for env A's endpoint.
    $this->runAsEnvironment($envA->id, fn () => app(EventBus::class)->emit(new DomainEvent('user.created', ['n' => 1])));
    $this->runAsEnvironment('unrelated-env', fn () => app(EventBus::class)->flushPending());

    Http::assertSentCount(1);
});
