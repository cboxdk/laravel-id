<?php

declare(strict_types=1);

use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * What minting and checking a token asks the database.
 *
 * WHY THIS FILE EXISTS. Each statement is a network round trip (1.2 ms or more on
 * production, 2026-11-12), and the token endpoint and introspection run on every call
 * between services. These tests hold the statements that were sent without a reason: an
 * UPDATE that changed nothing, a signing key read twice in one request, and a lookup of a
 * person for a token that has none.
 */

/** @return list<string> the SQL a callback sent */
function statementsDuring(Closure $callback): array
{
    $statements = [];
    DB::listen(function (QueryExecuted $query) use (&$statements): void {
        $statements[] = $query->sql;
    });

    $callback();

    return $statements;
}

/** A new request in the same environment: scoped instances are what a request owns. */
function startNextRequest(): void
{
    $environment = app(EnvironmentContext::class)->current();
    app()->forgetScopedInstances();
    app(EnvironmentContext::class)->set($environment);
}

it('does not send the last-used UPDATE for a client that was stamped within the hour', function (): void {
    $client = $this->makeClient(['api.read'])->client;
    app(TokenIssuer::class)->issueClientCredentials($client, ['api.read']);
    $client->refresh();

    $statements = statementsDuring(fn () => app(TokenIssuer::class)->issueClientCredentials($client, ['api.read']));

    expect($client->last_used_at)->not->toBeNull()
        ->and(collect($statements)->filter(fn (string $sql): bool => str_starts_with($sql, 'update'))->all())->toBe([]);
});

it('stamps a client again once the hour has passed', function (): void {
    $client = $this->makeClient(['api.read'])->client;
    app(TokenIssuer::class)->issueClientCredentials($client, ['api.read']);
    $first = $client->refresh()->last_used_at;

    $this->travel(61)->minutes();
    app(TokenIssuer::class)->issueClientCredentials($client, ['api.read']);

    expect($client->refresh()->last_used_at->greaterThan($first))->toBeTrue();
});

it('reads the active signing key once per request', function (): void {
    $keys = app(KeyManager::class);
    $keys->activeSigningKey();
    startNextRequest();

    $statements = statementsDuring(function () use ($keys): void {
        $keys->activeSigningKey();
        $keys->activeSigningKey();
        $keys->activeSigningKey();
    });

    expect($statements)->toHaveCount(1);
});

it('signs with the new key at once after a rotation in the same request', function (): void {
    $keys = app(KeyManager::class);
    $old = $keys->activeSigningKey()->kid;

    $new = $keys->rotate()->kid;

    expect($keys->activeSigningKey()->kid)->toBe($new)->not->toBe($old);
});

it('reads the signing key again on the next request', function (): void {
    $keys = app(KeyManager::class);
    $keys->activeSigningKey();
    startNextRequest();

    expect(statementsDuring(fn () => $keys->activeSigningKey()))->toHaveCount(1);
});

it('does not look for a person behind a client-credentials token', function (): void {
    $client = $this->makeClient(['api.read'])->client;
    $token = app(TokenIssuer::class)->issueClientCredentials($client, ['api.read'])->token;

    $statements = statementsDuring(fn () => expect(app(TokenIntrospector::class)->introspect($token)->active)->toBeTrue());

    expect(collect($statements)->filter(fn (string $sql): bool => str_contains($sql, 'users'))->all())->toBe([]);
});

it('still refuses a person\'s token once the person is disabled', function (): void {
    User::query()->create(['id' => 'alice', 'email' => 'alice@tokens.test', 'status' => UserStatus::Active]);
    $client = $this->makeClient(['openid'])->client;
    $token = app(TokenIssuer::class)->issueForUser($client, 'alice', null, ['openid'])->token;

    expect(app(TokenIntrospector::class)->introspect($token)->active)->toBeTrue();

    User::query()->whereKey('alice')->update(['status' => UserStatus::Disabled]);

    expect(app(TokenIntrospector::class)->introspect($token)->active)->toBeFalse();
});
