<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\RelationshipStore;
use Cbox\Id\Kernel\Authorization\ValueObjects\Relationship;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

function batchToken(): string
{
    $registered = test()->makeClient(['openid']);

    return app(TokenIssuer::class)->issueForUser($registered->client, 'alice', 'org_x', ['openid'])->token;
}

/**
 * @param  list<array{relation: string, resource: string}>  $permissions
 */
function decide(string $token, array $permissions): TestResponse
{
    return test()->postJson(
        '/oauth/decisions',
        ['permissions' => $permissions],
        ['Authorization' => 'Bearer '.$token],
    );
}

it('refuses a batch larger than the configured cap', function (): void {
    $token = batchToken();
    config(['cbox-id.oauth.decisions.max_batch' => 3]);

    $permissions = array_map(
        static fn (int $i): array => ['relation' => 'view', 'resource' => 'ticket:'.$i],
        range(1, 4),
    );

    decide($token, $permissions)
        ->assertStatus(422)
        ->assertJsonPath('error', 'batch_too_large');
});

it('refuses an oversized entitlement batch too', function (): void {
    $token = batchToken();
    config(['cbox-id.oauth.decisions.max_batch' => 2]);

    $this->postJson('/oauth/decisions', ['entitlements' => ['a', 'b', 'c']], ['Authorization' => 'Bearer '.$token])
        ->assertStatus(422)
        ->assertJsonPath('error', 'batch_too_large');
});

it('still answers a batch at exactly the cap', function (): void {
    $token = batchToken();
    config(['cbox-id.oauth.decisions.max_batch' => 3]);

    decide($token, array_map(
        static fn (int $i): array => ['relation' => 'view', 'resource' => 'ticket:'.$i],
        range(1, 3),
    ))->assertOk()->assertJsonCount(3, 'permissions');
});

it('evaluates a repeated check once, not once per occurrence', function (): void {
    $token = batchToken();

    // A ten-hop userset chain: each hop is two queries, so one uncached check is
    // expensive and a repeated one is expensive again.
    $store = app(RelationshipStore::class);
    foreach (range(0, 9) as $hop) {
        $store->write(new Relationship('org_x', 'ticket', (string) $hop, 'view', 'ticket', (string) ($hop + 1), 'view'));
    }
    $store->write(new Relationship('org_x', 'ticket', '10', 'view', 'user', 'alice'));

    $once = ['relation' => 'view', 'resource' => 'ticket:0'];

    // Warm the per-request caches that are not what is being measured here (the
    // environment resolution, the entitlement version), so the two figures below
    // differ only in how many times the graph was walked.
    decide($token, [$once]);

    $queriesForOne = decisionQueries(fn () => decide($token, [$once]));
    $queriesForTen = decisionQueries(fn () => decide($token, array_fill(0, 10, $once)));

    // Repeating the SAME (relation, resource) ten times costs no more graph walking
    // than asking once — the org and subject are fixed for the whole batch, so the
    // answer cannot differ between occurrences.
    expect($queriesForTen)->toBe($queriesForOne);
});

it('still evaluates distinct checks separately', function (): void {
    $token = batchToken();

    app(RelationshipStore::class)->write(new Relationship('org_x', 'ticket', '1', 'view', 'user', 'alice'));

    decide($token, [
        ['relation' => 'view', 'resource' => 'ticket:1'],
        ['relation' => 'view', 'resource' => 'ticket:2'],
    ])
        ->assertOk()
        ->assertJsonPath('permissions.0.allowed', true)
        ->assertJsonPath('permissions.1.allowed', false);
});

/** Queries issued while handling one decision request. */
function decisionQueries(Closure $callback): int
{
    $count = 0;
    DB::listen(function () use (&$count): void {
        $count++;
    });

    $callback();

    return $count;
}
