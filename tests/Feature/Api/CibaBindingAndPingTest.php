<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\BackchannelTokenDeliveryMode;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Jobs\NotifyCibaClient;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\GuardPolicy;
use Cbox\Ssrf\Testing\FakeResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;

uses(RefreshDatabase::class);

const CIBA_PING_GRANT = 'urn:openid:params:grant-type:ciba';
const CIBA_PING_ENDPOINT = 'https://dash.example/webhooks/cbox-id/ciba';

/** @return array<string, mixed> the payload of a JWT, unverified (the signature is tested elsewhere) */
function cibaJwtClaims(string $jwt): array
{
    $payload = json_decode(Base64Url::decode(explode('.', $jwt)[1]), true);

    return is_array($payload) ? $payload : [];
}

function cibaPingClient(Client $client): Client
{
    return app(ClientRegistry::class)->configureBackchannelTokenDelivery($client, BackchannelTokenDeliveryMode::Ping, CIBA_PING_ENDPOINT);
}

function cibaEnvironment(): string
{
    return (string) app(EnvironmentContext::class)->current()?->environmentKey();
}

/** Redeem an approved request at the token endpoint. */
function cibaRedeem(object $test, object $registered, string $authReqId, array $extra = []): array
{
    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);

    return $test->postJson('/oauth/token', [
        'grant_type' => CIBA_PING_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $authReqId,
        ...$extra,
    ])->assertOk()->json();
}

// ---------------------------------------------------------------------------------------
// Bound tokens: what the approval was for
// ---------------------------------------------------------------------------------------

it('puts the auth_req_id and the binding message on the access token and the ID Token', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]);
    $user = $this->makeUser('bound@example.test');

    $start = $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
        'login_hint' => $user->id,
        'binding_message' => 'Approve plan 3f9a2c41d0b7',
    ])->assertOk();

    $authReqId = (string) $start->json('auth_req_id');
    $request = BackchannelAuthRequest::query()->sole();
    app(BackchannelAuthentication::class)->approve($request->id, $user->id);

    $body = cibaRedeem($this, $registered, $authReqId);

    foreach ([$body['access_token'], $body['id_token']] as $jwt) {
        $claims = cibaJwtClaims((string) $jwt);

        expect($claims['auth_req_id'] ?? null)->toBe($authReqId)
            ->and($claims['binding_message'] ?? null)->toBe('Approve plan 3f9a2c41d0b7');
    }
});

it('omits binding_message when none was sent, and keeps auth_req_id', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]);
    $user = $this->makeUser('nomsg@example.test');
    $ciba = app(BackchannelAuthentication::class);

    $result = $ciba->request($registered->client, ['openid'], $user->id);
    $ciba->approve($result->requestId, $user->id);

    $claims = cibaJwtClaims((string) cibaRedeem($this, $registered, $result->authReqId)['access_token']);

    expect($claims['auth_req_id'] ?? null)->toBe($result->authReqId)
        ->and($claims)->not->toHaveKey('binding_message');
});

it('binds the token to its audience and the approval together', function (): void {
    // The engine's case: a resource-bound access token that also names the approval.
    config(['cbox-id.oauth.resource_indicators.unknown_resources' => 'accept']);
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]);
    $user = $this->makeUser('engine@example.test');
    $ciba = app(BackchannelAuthentication::class);

    $result = $ciba->request($registered->client, ['openid'], $user->id, 'plan 3f9a2c41d0b7', resource: 'https://engine.example');
    $ciba->approve($result->requestId, $user->id);

    $claims = cibaJwtClaims((string) cibaRedeem($this, $registered, $result->authReqId)['access_token']);

    expect((array) $claims['aud'])->toContain('https://engine.example')
        ->and($claims['auth_req_id'] ?? null)->toBe($result->authReqId)
        ->and($claims['binding_message'] ?? null)->toBe('plan 3f9a2c41d0b7');
});

it('puts no binding on tokens from any other grant', function (): void {
    $registered = $this->makeClient(['openid', 'offline_access'], grantTypes: [CIBA_PING_GRANT, 'refresh_token', 'client_credentials']);
    $user = $this->makeUser('other@example.test');
    $ciba = app(BackchannelAuthentication::class);

    $machine = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])->assertOk()->json();

    expect(cibaJwtClaims((string) $machine['access_token']))->not->toHaveKey('auth_req_id');

    // A refresh of a CIBA grant is not the approval: the refreshed tokens carry no binding.
    $result = $ciba->request($registered->client, ['openid', 'offline_access'], $user->id, 'plan abc');
    $ciba->approve($result->requestId, $user->id);
    $first = cibaRedeem($this, $registered, $result->authReqId);

    $refreshed = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'refresh_token' => $first['refresh_token'],
    ])->assertOk()->json();

    foreach ([$refreshed['access_token'], $refreshed['id_token']] as $jwt) {
        expect(cibaJwtClaims((string) $jwt))->not->toHaveKey('auth_req_id')
            ->and(cibaJwtClaims((string) $jwt))->not->toHaveKey('binding_message');
    }
});

it('takes the binding from the row the redeem lock holds, and mints it once', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]);
    $user = $this->makeUser('lock@example.test');
    $ciba = app(BackchannelAuthentication::class);

    $result = $ciba->request($registered->client, ['openid'], $user->id, 'the approved message');
    $ciba->approve($result->requestId, $user->id);

    // Read under the lock: a binding changed after the poll's first read but before the
    // locked read is the one the token carries — the locked row is the request redeemed.
    $grant = DB::transaction(fn () => $ciba->redeem($registered->client->client_id, $result->authReqId));

    expect($grant->backchannel?->authReqId)->toBe($result->authReqId)
        ->and($grant->backchannel?->bindingMessage)->toBe('the approved message');

    // Spent: a second redemption is refused, so no second bound token exists.
    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);
    $this->postJson('/oauth/token', [
        'grant_type' => CIBA_PING_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

// ---------------------------------------------------------------------------------------
// Ping mode: registration
// ---------------------------------------------------------------------------------------

it('advertises poll and ping at the discovery endpoint', function (): void {
    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('backchannel_token_delivery_modes_supported', ['poll', 'ping']);
});

it('leaves every client in poll mode until an operator registers ping', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]);

    expect($registered->client->backchannelTokenDeliveryMode())->toBe(BackchannelTokenDeliveryMode::Poll)
        ->and($registered->client->backchannel_token_delivery_mode)->toBeNull();
});

it('registers ping with an https endpoint and audits the change', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]);

    $client = cibaPingClient($registered->client)->refresh();

    expect($client->backchannelTokenDeliveryMode())->toBe(BackchannelTokenDeliveryMode::Ping)
        ->and($client->backchannel_client_notification_endpoint)->toBe(CIBA_PING_ENDPOINT)
        ->and(AuditEntry::query()->where('action', 'app.updated')->exists())->toBeTrue();

    // Back to poll clears the endpoint.
    $client = app(ClientRegistry::class)->configureBackchannelTokenDelivery($client, BackchannelTokenDeliveryMode::Poll, CIBA_PING_ENDPOINT)->refresh();

    expect($client->backchannel_token_delivery_mode)->toBeNull()
        ->and($client->backchannel_client_notification_endpoint)->toBeNull();
});

it('refuses ping without an https endpoint', function (?string $endpoint): void {
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]);

    expect(fn () => app(ClientRegistry::class)->configureBackchannelTokenDelivery($registered->client, BackchannelTokenDeliveryMode::Ping, $endpoint))
        ->toThrow(InvalidClientMetadata::class);
})->with([
    'none' => [null],
    'blank' => ['  '],
    'http' => ['http://dash.example/ping'],
    'http on localhost' => ['http://localhost/ping'],
    'relative' => ['/ping'],
    'fragment' => ['https://dash.example/ping#x'],
    'credentials' => ['https://user:pw@dash.example/ping'],
]);

// ---------------------------------------------------------------------------------------
// Ping mode: the backchannel request
// ---------------------------------------------------------------------------------------

it('requires a client_notification_token from a ping-mode client, before anyone is prompted', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]);
    cibaPingClient($registered->client);
    $user = $this->makeUser('needs-token@example.test');

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
        'login_hint' => $user->id,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_request');

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
        'login_hint' => $user->id,
        'client_notification_token' => str_repeat('a', 1025),
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_request');

    expect(BackchannelAuthRequest::query()->count())->toBe(0);
});

it('stores the notification token and auth_req_id encrypted, for a ping-mode request only', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]);
    cibaPingClient($registered->client);
    $user = $this->makeUser('stored@example.test');

    $start = $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
        'login_hint' => $user->id,
        'client_notification_token' => 'ping-bearer-123',
    ])->assertOk();

    $row = BackchannelAuthRequest::query()->sole();
    $raw = DB::table('ciba_requests')->where('id', $row->id)->first();

    expect($row->client_notification_token)->toBe('ping-bearer-123')
        ->and($row->notification_auth_req_id)->toBe($start->json('auth_req_id'))
        // Encrypted at rest: neither raw value is in the column.
        ->and((string) $raw->client_notification_token)->not->toContain('ping-bearer-123')
        ->and((string) $raw->notification_auth_req_id)->not->toContain((string) $start->json('auth_req_id'))
        ->and($row->toArray())->not->toHaveKey('client_notification_token');
});

it('ignores a client_notification_token from a poll-mode client', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]);
    $user = $this->makeUser('poller@example.test');

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
        'login_hint' => $user->id,
        'client_notification_token' => 'unused',
    ])->assertOk();

    expect(DB::table('ciba_requests')->value('client_notification_token'))->toBeNull();
});

// ---------------------------------------------------------------------------------------
// Ping mode: the notification
// ---------------------------------------------------------------------------------------

/** A ping-mode request filed over HTTP; returns [registered, user, auth_req_id, request id]. */
function cibaPingRequest(object $test, string $email): array
{
    // The helpers are the TestCase's own (protected); called as the test.
    [$registered, $user] = (fn (): array => [$this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]), $this->makeUser($email)])->call($test);
    cibaPingClient($registered->client);

    $authReqId = (string) $test->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
        'login_hint' => $user->id,
        'binding_message' => 'plan 3f9a2c41d0b7',
        'client_notification_token' => 'ping-bearer-123',
    ])->assertOk()->json('auth_req_id');

    return [$registered, $user, $authReqId, BackchannelAuthRequest::query()->sole()->id];
}

it('queues a ping on approve and on deny, and none for a poll-mode request', function (): void {
    Queue::fake();

    [, $user, , $requestId] = cibaPingRequest($this, 'queued@example.test');
    app(BackchannelAuthentication::class)->approve($requestId, $user->id);

    Queue::assertPushed(NotifyCibaClient::class, fn (NotifyCibaClient $job): bool => $job->requestId === $requestId);

    BackchannelAuthRequest::query()->delete();
    [, $other, , $deniedId] = cibaPingRequest($this, 'denied@example.test');
    app(BackchannelAuthentication::class)->deny($deniedId, $other->id);

    Queue::assertPushed(NotifyCibaClient::class, fn (NotifyCibaClient $job): bool => $job->requestId === $deniedId);

    // Poll mode: nothing queued.
    $poller = $this->makeClient(['openid'], grantTypes: [CIBA_PING_GRANT]);
    $person = $this->makeUser('poll-only@example.test');
    $ciba = app(BackchannelAuthentication::class);
    $result = $ciba->request($poller->client, ['openid'], $person->id);
    $ciba->approve($result->requestId, $person->id);

    Queue::assertPushed(NotifyCibaClient::class, 2);
});

it('POSTs the auth_req_id as JSON with the bearer token, then forgets both', function (): void {
    config(['cbox-id.oauth.ciba.ping.verify_url' => false]);
    Http::fake(['dash.example/*' => Http::response('', 204)]);

    [$registered, $user, $authReqId, $requestId] = cibaPingRequest($this, 'ping@example.test');
    app(BackchannelAuthentication::class)->approve($requestId, $user->id);

    Http::assertSent(fn (Request $request): bool => $request->url() === CIBA_PING_ENDPOINT
        && $request->method() === 'POST'
        && $request->hasHeader('Authorization', 'Bearer ping-bearer-123')
        && $request->isJson()
        && $request->data() === ['auth_req_id' => $authReqId]);

    $row = DB::table('ciba_requests')->where('id', $requestId)->first();

    expect($row->client_notification_token)->toBeNull()
        ->and($row->notification_auth_req_id)->toBeNull()
        ->and(AuditEntry::query()->where('action', 'oauth.ciba.notified')->exists())->toBeTrue();

    // The client then redeems once, and gets the bound token.
    $claims = cibaJwtClaims((string) cibaRedeem($this, $registered, $authReqId)['access_token']);
    expect($claims['auth_req_id'] ?? null)->toBe($authReqId);
});

it('pings on deny too, so the client learns of it without polling', function (): void {
    config(['cbox-id.oauth.ciba.ping.verify_url' => false]);
    Http::fake(['dash.example/*' => Http::response('', 200)]);

    [, $user, $authReqId, $requestId] = cibaPingRequest($this, 'ping-deny@example.test');
    app(BackchannelAuthentication::class)->deny($requestId, $user->id);

    Http::assertSent(fn (Request $request): bool => $request->data() === ['auth_req_id' => $authReqId]);
});

it('delivers from a worker with no ambient environment', function (): void {
    config(['cbox-id.oauth.ciba.ping.verify_url' => false]);
    Queue::fake();

    [, $user, $authReqId, $requestId] = cibaPingRequest($this, 'worker@example.test');
    app(BackchannelAuthentication::class)->approve($requestId, $user->id);
    $environment = cibaEnvironment();

    Http::fake(['dash.example/*' => Http::response('', 200)]);
    app(EnvironmentContext::class)->set(null);

    // Run as a worker would; dispatchSync would only be recorded by the faked queue.
    app()->call([new NotifyCibaClient($environment, $requestId), 'handle']);

    Http::assertSent(fn (Request $request): bool => $request->data() === ['auth_req_id' => $authReqId]);
});

it('retries a server error with a short backoff and gives up after max_attempts', function (): void {
    config(['cbox-id.oauth.ciba.ping.verify_url' => false, 'cbox-id.oauth.ciba.ping.max_attempts' => 3]);
    Queue::fake();
    Http::fake(['dash.example/*' => Http::response('', 503)]);

    [, $user, , $requestId] = cibaPingRequest($this, 'retry@example.test');
    app(BackchannelAuthentication::class)->approve($requestId, $user->id);

    $job = (new NotifyCibaClient(cibaEnvironment(), $requestId))->withFakeQueueInteractions();
    app()->call([$job, 'handle']);

    $job->assertReleased(2);
    expect($job->tries)->toBe(3)
        ->and(DB::table('ciba_requests')->where('id', $requestId)->value('client_notification_token'))->not->toBeNull();

    $last = (new NotifyCibaClient(cibaEnvironment(), $requestId))->withFakeQueueInteractions();
    $last->job->attempts = 3;
    app()->call([$last, 'handle']);

    $last->assertNotReleased();
    expect(DB::table('ciba_requests')->where('id', $requestId)->value('client_notification_token'))->toBeNull()
        ->and(AuditEntry::query()->where('action', 'oauth.ciba.notification_failed')->exists())->toBeTrue();
});

it('gives up at once on a client error', function (): void {
    config(['cbox-id.oauth.ciba.ping.verify_url' => false]);
    Queue::fake();
    Http::fake(['dash.example/*' => Http::response('', 401)]);

    [, $user, , $requestId] = cibaPingRequest($this, 'rejected@example.test');
    app(BackchannelAuthentication::class)->approve($requestId, $user->id);

    $job = (new NotifyCibaClient(cibaEnvironment(), $requestId))->withFakeQueueInteractions();
    app()->call([$job, 'handle']);

    $job->assertNotReleased();
    expect(AuditEntry::query()->where('action', 'oauth.ciba.notification_failed')->exists())->toBeTrue();
});

it('refuses an endpoint that resolves to a private address', function (): void {
    config(['cbox-id.oauth.ciba.ping.verify_url' => true]);
    app()->instance(Resolver::class, new FakeResolver(['dash.example' => ['10.0.0.5']]));
    app()->forgetInstance(GuardPolicy::class);
    app()->forgetInstance(UrlGuard::class);
    Queue::fake();
    Http::fake();

    [, $user, , $requestId] = cibaPingRequest($this, 'ssrf@example.test');
    app(BackchannelAuthentication::class)->approve($requestId, $user->id);

    $job = (new NotifyCibaClient(cibaEnvironment(), $requestId))->withFakeQueueInteractions();
    app()->call([$job, 'handle']);

    Http::assertNothingSent();
    expect(AuditEntry::query()->where('action', 'oauth.ciba.notification_failed')->exists())->toBeTrue();
});

it('sends nothing once the client redeemed first, and the redeem clears the secrets', function (): void {
    config(['cbox-id.oauth.ciba.ping.verify_url' => false]);
    Queue::fake();
    Http::fake();

    [$registered, $user, $authReqId, $requestId] = cibaPingRequest($this, 'early@example.test');
    app(BackchannelAuthentication::class)->approve($requestId, $user->id);

    cibaRedeem($this, $registered, $authReqId);

    expect(DB::table('ciba_requests')->where('id', $requestId)->value('client_notification_token'))->toBeNull();

    app()->call([new NotifyCibaClient(cibaEnvironment(), $requestId), 'handle']);

    Http::assertNothingSent();
});
