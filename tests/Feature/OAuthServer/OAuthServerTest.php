<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Enums\ClientType;
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
