<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\ServiceAccounts;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\UnknownServiceAccount;
use Cbox\Id\OAuthServer\Models\ServiceAccount;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('registers a confidential client and verifies its secret', function (): void {
    $registered = $this->makeClient(['api.read', 'api.write']);

    expect($registered->secret)->toStartWith('csec_')
        ->and($registered->client->secret_hash)->not->toBe($registered->secret)
        ->and(app(ClientRegistry::class)->verifySecret($registered->client, $registered->secret ?? ''))->toBeTrue()
        ->and(app(ClientRegistry::class)->verifySecret($registered->client, 'wrong'))->toBeFalse();
});

it('registers a public client with no secret', function (): void {
    $registered = $this->makeClient([], ClientType::Public);

    expect($registered->secret)->toBeNull()
        ->and(app(ClientRegistry::class)->verifySecret($registered->client, 'anything'))->toBeFalse();
});

it('creates a service account backed by a confidential client', function (): void {
    $org = $this->makeOrganization();
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    $registered = $this->makeServiceAccount($org->id, ['api.read']);

    expect($registered->secret)->not->toBeNull()
        ->and($registered->client->type)->toBe(ClientType::Confidential);
    $events->assertEmitted('service_account.created');
    $audit->assertRecorded('service_account.created');
});

it('issues a client-credentials token that introspects as active', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);

    $result = app(TokenIntrospector::class)->introspect($token->token);

    expect($result->active)->toBeTrue()
        ->and($result->subject)->toBe($registered->client->client_id)
        ->and($result->hasScope('api.read'))->toBeTrue();
});

it('narrows requested scopes to the client grants', function (): void {
    $registered = $this->makeClient(['api.read', 'api.write']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client, ['api.read', 'admin']);

    $result = app(TokenIntrospector::class)->introspect($token->token);

    expect($result->scopes)->toBe(['api.read']); // admin was not granted
});

it('reports a tampered or unknown token as inactive', function (): void {
    $introspector = app(TokenIntrospector::class);

    expect($introspector->introspect('not-a-jwt')->active)->toBeFalse()
        ->and($introspector->introspect('a.b.c')->active)->toBeFalse();
});

it('revokes a token', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);
    $introspector = app(TokenIntrospector::class);

    expect($introspector->introspect($token->token)->active)->toBeTrue();

    $introspector->revoke($token->jti);

    expect($introspector->introspect($token->token)->active)->toBeFalse();
});

it('issues a user token whose subject is the user', function (): void {
    $registered = $this->makeClient(['profile']);
    $token = app(TokenIssuer::class)->issueForUser($registered->client, 'user_1', 'org_a', ['profile']);

    $result = app(TokenIntrospector::class)->introspect($token->token);

    expect($result->subject)->toBe('user_1')
        ->and($result->hasScope('profile'))->toBeTrue();
});

it('overlap-rotates a service account: the successor works while the old still does', function (): void {
    // Fake the bus before anything resolves the service, so it captures its events.
    $events = $this->fakeEvents();
    $org = $this->makeOrganization();
    $accounts = app(ServiceAccounts::class);
    $issuer = app(TokenIssuer::class);
    $introspect = app(TokenIntrospector::class);

    $original = $this->makeServiceAccount($org->id, ['api.read', 'api.write']);
    $oldToken = $issuer->issueClientCredentials($original->client);

    $successor = $accounts->rotate($org->id, $original->client->client_id);

    // A distinct credential with the same privileges, linked to its predecessor.
    expect($successor->client->client_id)->not->toBe($original->client->client_id)
        ->and($successor->secret)->toStartWith('csec_')
        ->and($successor->client->scopes)->toBe(['api.read', 'api.write'])
        ->and(ServiceAccount::query()->where('client_id', $successor->client->client_id)->value('rotated_from'))
        ->toBe($original->client->client_id);
    $events->assertEmitted('service_account.rotated');

    // Overlap: BOTH credentials mint valid tokens until the old one is retired.
    $newToken = $issuer->issueClientCredentials($successor->client);
    expect($introspect->introspect($oldToken->token)->active)->toBeTrue()
        ->and($introspect->introspect($newToken->token)->active)->toBeTrue();
});

it('retires the old account after cutover: it cannot mint tokens and its tokens are revoked', function (): void {
    $org = $this->makeOrganization();
    $accounts = app(ServiceAccounts::class);
    $issuer = app(TokenIssuer::class);
    $introspect = app(TokenIntrospector::class);

    $original = $this->makeServiceAccount($org->id, ['api.read']);
    $oldToken = $issuer->issueClientCredentials($original->client);
    $successor = $accounts->rotate($org->id, $original->client->client_id);
    $newToken = $issuer->issueClientCredentials($successor->client);

    $accounts->retire($org->id, $original->client->client_id);

    expect(app(ClientRegistry::class)->byClientId($original->client->client_id))->toBeNull() // no new tokens
        ->and($introspect->introspect($oldToken->token)->active)->toBeFalse()               // existing revoked
        ->and($introspect->introspect($newToken->token)->active)->toBeTrue()                // successor untouched
        ->and(ServiceAccount::query()->where('client_id', $original->client->client_id)->value('status'))->toBe('retired');

    // Retiring again is a no-op, not an error.
    $accounts->retire($org->id, $original->client->client_id);
});

it('refuses to rotate or retire a service account owned by another org', function (): void {
    $orgA = $this->makeOrganization();
    $orgB = $this->makeOrganization();
    $accounts = app(ServiceAccounts::class);

    $victim = $this->makeServiceAccount($orgB->id, ['api.read']);

    // org A cannot touch org B's account even knowing its client_id, and the
    // refusal is indistinguishable from "no such account".
    expect(fn () => $accounts->rotate($orgA->id, $victim->client->client_id))->toThrow(UnknownServiceAccount::class)
        ->and(fn () => $accounts->retire($orgA->id, $victim->client->client_id))->toThrow(UnknownServiceAccount::class);

    // org B still owns it.
    expect($accounts->rotate($orgB->id, $victim->client->client_id)->client->client_id)->not->toBe($victim->client->client_id);
});

it('rejects rotating or retiring an unknown service account', function (): void {
    expect(fn () => app(ServiceAccounts::class)->rotate('org_unknown', 'unknown'))->toThrow(UnknownServiceAccount::class)
        ->and(fn () => app(ServiceAccounts::class)->retire('org_unknown', 'unknown'))->toThrow(UnknownServiceAccount::class);
});
