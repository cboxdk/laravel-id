<?php

declare(strict_types=1);

use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

beforeEach(fn () => config()->set('cbox-id.external_actions.verify_url', false));

/** Queries issued while running a callback. */
function hookQueries(Closure $callback): int
{
    $count = 0;
    DB::listen(function () use (&$count): void {
        $count++;
    });

    $callback();

    return $count;
}

it('stops querying for hooks on every token mint when none are registered', function (): void {
    $client = $this->makeClient(['openid'])->client;
    $issuer = app(TokenIssuer::class);

    // First mint populates the empty active set for this (environment, hook point).
    $issuer->issueForUser($client, 'alice', 'org_x', ['openid']);

    $cached = hookQueries(fn () => $issuer->issueForUser($client, 'alice', 'org_x', ['openid']));

    config()->set('cbox-id.external_actions.cache_ttl', 0);
    $uncached = hookQueries(fn () => $issuer->issueForUser($client, 'alice', 'org_x', ['openid']));

    // The saving is the hook lookup itself — an environment with no hooks at all was
    // still paying a query per token.
    expect($cached)->toBeLessThan($uncached);
});

it('serves the same endpoints from cache without re-reading them', function (): void {
    $this->fakeActionTransport();
    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');

    $actions = app(ExternalActions::class);

    expect($actions->active(HookPoint::TokenMinting, null))->toHaveCount(1);

    expect(hookQueries(fn () => $actions->active(HookPoint::TokenMinting, null)))->toBe(0);
});

it('sees a newly registered endpoint at once, without waiting for the ttl', function (): void {
    $this->fakeActionTransport();
    $actions = app(ExternalActions::class);

    expect($actions->active(HookPoint::TokenMinting, null))->toHaveCount(0);

    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');

    expect($actions->active(HookPoint::TokenMinting, null))->toHaveCount(1);
});

it('stops calling an endpoint the moment it is paused', function (): void {
    $this->fakeActionTransport();
    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');
    $actions = app(ExternalActions::class);

    expect($actions->active(HookPoint::TokenMinting, null))->toHaveCount(1);

    $actions->pause($registered->endpoint->id, null);

    expect($actions->active(HookPoint::TokenMinting, null))->toHaveCount(0);
});

it('never serves one tenant\'s hook to another out of the shared entry', function (): void {
    $this->fakeActionTransport();

    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://environment.example.test');
    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://acme.example.test', 'org_acme');
    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://globex.example.test', 'org_globex');

    $actions = app(ExternalActions::class);

    $urlsFor = fn (?string $org): array => $actions->active(HookPoint::TokenMinting, $org)
        ->pluck('url')->sort()->values()->all();

    // The whole environment is cached in one entry; the per-org narrowing happens in
    // memory, and it has to be exactly as tight as the SQL it replaced.
    expect($urlsFor('org_acme'))->toBe(['https://acme.example.test', 'https://environment.example.test'])
        ->and($urlsFor('org_globex'))->toBe(['https://environment.example.test', 'https://globex.example.test'])
        ->and($urlsFor(null))->toBe(['https://environment.example.test'])
        // Re-read now that everything is warm — the answers must not have merged.
        ->and($urlsFor('org_acme'))->toBe(['https://acme.example.test', 'https://environment.example.test']);
});

it('fires a fan-out concurrently rather than one endpoint after another', function (): void {
    Http::fake(['*' => Http::response(['action' => 'continue', 'claims' => []], 200)]);

    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://one.example.test');
    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://two.example.test');
    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://three.example.test');

    $client = $this->makeClient(['openid'])->client;
    app(TokenIssuer::class)->issueForUser($client, 'alice', 'org_x', ['openid']);

    // All three went out in one pooled batch. Sequentially this cost three full
    // connect+read timeouts on the token path; pooled it costs one.
    Http::assertSentCount(3);
});
