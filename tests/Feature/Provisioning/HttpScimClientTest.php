<?php

declare(strict_types=1);

use Cbox\Id\Provisioning\Contracts\ScimClient;
use Cbox\Id\Provisioning\Enums\AuthScheme;
use Cbox\Id\Scim\ScimSchema;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['cbox-id.provisioning.verify_url' => false]);
});

it('POSTs a real scim+json User body with a bearer token', function (): void {
    Http::fake(['*' => Http::response(json_encode(['id' => 'remote-1', 'externalId' => 'user-1']), 201)]);
    $connection = $this->registerProvisioningConnection(secret: 'the-bearer-token')->connection;

    $resource = ScimSchema::userResource('user-1', ['userName' => 'u@example.com', 'active' => true]);
    $result = app(ScimClient::class)->createUser($connection, $resource);

    expect($result->status)->toBe(201)
        ->and($result->remoteId())->toBe('remote-1');

    Http::assertSent(function (Request $request): bool {
        $body = json_decode($request->body(), true);

        return $request->method() === 'POST'
            && $request->url() === 'https://scim.downstream.test/scim/v2/Users'
            && $request->header('Authorization')[0] === 'Bearer the-bearer-token'
            && str_contains($request->header('Content-Type')[0], 'application/scim+json')
            && $body['schemas'] === [ScimSchema::USER_URN]
            && $body['externalId'] === 'user-1';
    });
});

it('PATCHes a PatchOp body to the remote id and GETs a filter for reconcile', function (): void {
    // A correctly-filtered SCIM ListResponse: exactly the record carrying our externalId.
    Http::fake(['*' => Http::response(json_encode(['schemas' => [ScimSchema::LIST_RESPONSE_URN], 'totalResults' => 1, 'Resources' => [['id' => 'remote-9', 'externalId' => 'user-1']]]), 200)]);
    $connection = $this->registerProvisioningConnection()->connection;

    app(ScimClient::class)->patchUser($connection, 'remote-9', [ScimSchema::setActive(false)]);
    $found = app(ScimClient::class)->findByExternalId($connection, 'user-1');

    expect($found)->toBe('remote-9');

    Http::assertSent(function (Request $request): bool {
        if ($request->method() !== 'PATCH') {
            return false;
        }
        $body = json_decode($request->body(), true);

        return $request->url() === 'https://scim.downstream.test/scim/v2/Users/remote-9'
            && $body['schemas'] === [ScimSchema::PATCH_OP_URN]
            && $body['Operations'][0] === ['op' => 'replace', 'path' => 'active', 'value' => false];
    });

    Http::assertSent(fn (Request $request): bool => $request->method() === 'GET'
        && str_contains(urldecode($request->url()), 'filter=externalId eq "user-1"'));
});

it('refuses a reconcile match from a server that ignores the filter and returns its whole list', function (): void {
    // A lenient/misconfigured SCIM peer ignores the unknown filter and returns every
    // user with 200. We must NOT adopt an arbitrary record as this subject's mirror.
    Http::fake(['*' => Http::response(json_encode([
        'schemas' => [ScimSchema::LIST_RESPONSE_URN],
        'totalResults' => 3,
        'Resources' => [
            ['id' => 'someone-else-1', 'externalId' => 'user-999'],
            ['id' => 'someone-else-2', 'externalId' => 'user-888'],
            ['id' => 'someone-else-3', 'externalId' => 'user-777'],
        ],
    ]), 200)]);
    $connection = $this->registerProvisioningConnection()->connection;

    expect(app(ScimClient::class)->findByExternalId($connection, 'user-1'))->toBeNull();
});

it('refuses a single reconcile result whose externalId does not actually match', function (): void {
    // Even a single-result response must carry the requested externalId — otherwise
    // the server matched on something else (or fabricated a row).
    Http::fake(['*' => Http::response(json_encode([
        'schemas' => [ScimSchema::LIST_RESPONSE_URN],
        'totalResults' => 1,
        'Resources' => [['id' => 'wrong-user', 'externalId' => 'user-2']],
    ]), 200)]);
    $connection = $this->registerProvisioningConnection()->connection;

    expect(app(ScimClient::class)->findByExternalId($connection, 'user-1'))->toBeNull();
});

it('exchanges an OAuth2 client-credentials grant for the bearer it presents', function (): void {
    Http::fake([
        'https://idp.downstream.test/token' => Http::response(json_encode(['access_token' => 'minted-access-token', 'token_type' => 'Bearer']), 200),
        'https://scim.downstream.test/*' => Http::response(json_encode(['id' => 'remote-2']), 201),
    ]);

    $connection = $this->registerProvisioningConnection(
        authScheme: AuthScheme::OAuth2ClientCredentials,
        secret: 'oauth-client-secret',
        authConfig: [
            'token_url' => 'https://idp.downstream.test/token',
            'client_id' => 'client-abc',
            'scope' => 'scim',
        ],
    )->connection;

    app(ScimClient::class)->createUser($connection, ScimSchema::userResource('user-2', ['userName' => 'x@example.com']));

    // The token endpoint got a standard client-credentials form grant.
    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://idp.downstream.test/token'
        && $request['grant_type'] === 'client_credentials'
        && $request['client_id'] === 'client-abc'
        && $request['client_secret'] === 'oauth-client-secret');

    // The SCIM call presented the minted access token, not the client secret.
    Http::assertSent(fn (Request $request): bool => str_starts_with($request->url(), 'https://scim.downstream.test/')
        && $request->header('Authorization')[0] === 'Bearer minted-access-token');
});

it('refreshes an expired OAuth access token instead of reusing a stale one', function (): void {
    // The client is a container singleton living across many jobs in a worker; a
    // cache with no expiry would serve a dead token forever and 401 every op.
    Http::fake([
        'https://idp.downstream.test/token' => Http::sequence()
            ->push(json_encode(['access_token' => 'token-1', 'expires_in' => 100]), 200)
            ->push(json_encode(['access_token' => 'token-2', 'expires_in' => 100]), 200),
        'https://scim.downstream.test/*' => Http::response(json_encode(['id' => 'r']), 201),
    ]);

    $connection = $this->registerProvisioningConnection(
        authScheme: AuthScheme::OAuth2ClientCredentials,
        secret: 'oauth-client-secret',
        authConfig: ['token_url' => 'https://idp.downstream.test/token', 'client_id' => 'client-abc'],
    )->connection;

    $client = app(ScimClient::class);

    // First op mints token-1; a second op within the TTL reuses it (one token fetch).
    $client->createUser($connection, ScimSchema::userResource('user-1', ['userName' => 'a@example.com']));
    $client->createUser($connection, ScimSchema::userResource('user-2', ['userName' => 'b@example.com']));

    // Past the token's lifetime, the next op must mint a fresh token.
    $this->travel(200)->seconds();
    $client->createUser($connection, ScimSchema::userResource('user-3', ['userName' => 'c@example.com']));

    $tokenFetches = Http::recorded(fn (Request $request): bool => $request->url() === 'https://idp.downstream.test/token');
    expect($tokenFetches)->toHaveCount(2);

    // The op after expiry presented the refreshed token, not the stale one.
    $lastCreate = Http::recorded(fn (Request $request): bool => str_contains($request->url(), '/Users'))->last();
    expect($lastCreate[0]->header('Authorization')[0])->toBe('Bearer token-2');
});
