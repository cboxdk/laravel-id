<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;

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
