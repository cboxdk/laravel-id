<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\GrantPollStatus;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * Pest ignores a file-level `@group` docblock — membership comes only from a `uses()` or
 * a per-test `->group()`. So the 17 files that declared the group this way contributed
 * ZERO tests to `--group=isolation`, including the environment-isolation proof itself,
 * while docs/core-concepts/environments.md tells operators to run exactly that command
 * as the evidence. A selector that silently omits its own load-bearing file is worse than
 * no selector.
 */
uses()->group('isolation');

const CIBA_GRANT = 'urn:openid:params:grant-type:ciba';

it('starts a CIBA flow and returns only the client-facing auth_req_id', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);
    $user = $this->makeUser('alice@example.test');

    $response = $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
        'login_hint' => $user->id,
        'binding_message' => 'Approve deployment',
    ]);

    $response->assertOk()->assertJsonStructure(['auth_req_id', 'expires_in', 'interval']);

    expect($response->json('auth_req_id'))->toStartWith('auth_req_')
        // The internal approval handle is never leaked to the client.
        ->and($response->json())->not->toHaveKey('request_id')
        ->and($response->json())->not->toHaveKey('user_id');
});

it('polls pending, then issues access + id_token once the user approves', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);
    $user = $this->makeUser('bob@example.test');

    $ciba = app(BackchannelAuthentication::class);
    $result = $ciba->request($registered->client, ['openid'], $user->id);

    // While unapproved, the token endpoint answers authorization_pending.
    $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ])->assertStatus(400)->assertJsonPath('error', 'authorization_pending');

    // The user approves out-of-band, via the host's approval surface (internal id).
    expect($ciba->approve($result->requestId, $user->id, 'org-1'))->toBeTrue();

    // Skip the polling interval so the next poll isn't slow_down'd.
    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);

    $token = $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ])->assertOk();

    // CIBA is OIDC: an id_token is returned alongside the access token.
    expect($token->json('id_token'))->toBeString()->not->toBe('');

    $introspection = app(TokenIntrospector::class)->introspect((string) $token->json('access_token'));
    expect($introspection->active)->toBeTrue()
        ->and($introspection->subject)->toBe($user->id);
});

it('binds the request nonce into the issued id_token', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);
    $user = $this->makeUser('nonce@example.test');

    // The client supplies a nonce at CIBA initiation (CIBA Core §7.1). It must survive
    // to the id_token so the client can bind the token to this backchannel request.
    $init = $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
        'login_hint' => $user->id,
        'nonce' => 'ciba-nonce-xyz',
    ])->assertOk();

    $request = BackchannelAuthRequest::query()->firstOrFail();
    expect($request->nonce)->toBe('ciba-nonce-xyz');

    app(BackchannelAuthentication::class)->approve($request->id, $user->id);
    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);

    $token = $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $init->json('auth_req_id'),
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify((string) $token->json('id_token'), [SigningAlg::RS256]);
    expect($claims->get('nonce'))->toBe('ciba-nonce-xyz');
});

it('returns slow_down when polling faster than the interval', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);
    $user = $this->makeUser('carol@example.test');
    $result = app(BackchannelAuthentication::class)->request($registered->client, ['openid'], $user->id);

    $poll = fn () => $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ]);

    $poll()->assertJsonPath('error', 'authorization_pending'); // first poll allowed
    $poll()->assertJsonPath('error', 'slow_down');             // immediate re-poll throttled
});

it('reports denial and expiry', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);
    $user = $this->makeUser('dave@example.test');
    $ciba = app(BackchannelAuthentication::class);

    $denied = $ciba->request($registered->client, ['openid'], $user->id);
    $ciba->deny($denied->requestId, $user->id);
    $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT, 'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret, 'auth_req_id' => $denied->authReqId,
    ])->assertJsonPath('error', 'access_denied');

    $expired = $ciba->request($registered->client, ['openid'], $user->id);
    BackchannelAuthRequest::query()->whereKey($expired->requestId)->update(['expires_at' => now()->subMinute()]);
    $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT, 'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret, 'auth_req_id' => $expired->authReqId,
    ])->assertJsonPath('error', 'expired_token');
});

it('mints a token only once per auth_req_id (single-use)', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);
    $user = $this->makeUser('erin@example.test');
    $ciba = app(BackchannelAuthentication::class);
    $result = $ciba->request($registered->client, ['openid'], $user->id);
    $ciba->approve($result->requestId, $user->id);

    $poll = fn () => $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ]);

    $poll()->assertOk(); // first exchange succeeds

    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);

    // A second exchange with the same (leaked/observed) auth_req_id is refused.
    $poll()->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('rejects an unknown auth_req_id', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);

    $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT, 'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret, 'auth_req_id' => 'auth_req_nope',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('rejects a login_hint that resolves to no user', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
        'login_hint' => 'ghost@example.test',
    ])->assertStatus(400)->assertJsonPath('error', 'unknown_user_id');
});

it('rejects a backchannel request with no login_hint', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
});

it('rejects an unauthenticated backchannel request', function (): void {
    $user = $this->makeUser('frank@example.test');

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => 'nope',
        'login_hint' => $user->id,
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('advertises the CIBA endpoint, delivery mode and grant type in metadata', function (): void {
    config(['cbox-id.oauth.authorization_endpoint_path' => '/oauth/authorize']);

    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('backchannel_authentication_endpoint', fn (string $v): bool => str_ends_with($v, '/oauth/backchannel_authentication'))
        ->assertJsonPath('backchannel_token_delivery_modes_supported', ['poll'])
        ->assertJsonFragment(['grant_types_supported' => [
            'authorization_code', 'client_credentials', 'refresh_token',
            'urn:ietf:params:oauth:grant-type:device_code', CIBA_GRANT,
            'urn:ietf:params:oauth:grant-type:token-exchange',
        ]]);
});

/**
 * @group isolation
 *
 * CIBA approval IS the consent step: the token that follows is minted for the user the
 * request names, so approving is an act only that user may perform. The approval surface
 * lists only your own pending requests, but the id is the whole authorization — it also
 * travels in the oauth.backchannel_authentication_requested domain event to environment
 * webhooks, so it must not be the only thing standing between an agent and a token.
 */
it('refuses to approve or deny another subject\'s request', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);
    $victim = $this->makeUser('victim@example.test');
    $attacker = $this->makeUser('attacker@example.test');
    $ciba = app(BackchannelAuthentication::class);

    $pending = $ciba->request($registered->client, ['openid'], $victim->id);

    expect($ciba->approve($pending->requestId, $attacker->id, 'org-attacker'))->toBeFalse()
        ->and($ciba->deny($pending->requestId, $attacker->id))->toBeFalse();

    // Untouched: still pending, still unbound to the attacker's org.
    $row = BackchannelAuthRequest::query()->whereKey($pending->requestId)->firstOrFail();
    expect($row->status)->toBe(GrantPollStatus::Pending)
        ->and($row->organization_id)->toBeNull();

    // And no token can be redeemed off the back of the attempt.
    $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $pending->authReqId,
    ])->assertStatus(400)->assertJsonPath('error', 'authorization_pending');

    // The rightful subject still can.
    expect($ciba->approve($pending->requestId, $victim->id))->toBeTrue();
});

/**
 * CIBA must not accept a public client.
 *
 * `authenticate()` lets a public client through on `client_id` alone, which is safe where
 * a front channel and PKCE bind the flow to the browser that started it. CIBA has
 * neither: no redirect, no `code_verifier`, and the only human check is the approval
 * prompt this endpoint puts on someone's phone.
 *
 * So a public `client_id` — not a secret, and present in every copy of an app binary —
 * was enough to spray approval prompts at arbitrary users via `login_hint`. That attacks
 * exactly the human-in-the-loop that CIBA exists for: someone who has dismissed thirty
 * prompts approves the thirty-first.
 */
it('refuses a public client, which has no secret to prove anything with', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_GRANT], type: ClientType::Public);
    $user = $this->makeUser('target@example.test');

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'scope' => 'openid',
        'login_hint' => $user->id,
        'binding_message' => 'Approve deployment',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');

    expect(BackchannelAuthRequest::query()->count())->toBe(0, 'a prompt was created for an unauthenticated client');
});

/**
 * CIBA IS THE DECOUPLED FLOW: the client that starts it has no browser to bounce the
 * person through when an access token expires — that is the whole reason it exists.
 *
 * `offline_access` was accepted at the backchannel endpoint, carried on the grant, and
 * then dropped at redemption, so an approved agent was dead an hour later with no way back
 * but a second approval from the person it acts for. The device grant beside it had the
 * identical defect and was fixed; the reasoning was never carried one branch over.
 */
it('issues a refresh token when the CIBA client asked for offline access', function (): void {
    $registered = $this->makeClient(
        ['openid', 'offline_access'],
        grantTypes: [CIBA_GRANT, 'refresh_token'],
    );
    $user = $this->makeUser('agent@example.test');
    $ciba = app(BackchannelAuthentication::class);

    $result = $ciba->request($registered->client, ['openid', 'offline_access'], $user->id);
    expect($ciba->approve($result->requestId, $user->id, 'org-1'))->toBeTrue();

    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);

    $body = $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ])->assertOk()->json();

    expect($body['refresh_token'] ?? null)->toBeString()
        ->and($body['id_token'] ?? null)->toBeString();
});

it('issues no CIBA refresh token when offline access was not asked for', function (): void {
    // The scope is the request, not a default: a client that never asked for one must not
    // be handed a credential that outlives the person's attention.
    $registered = $this->makeClient(['openid'], grantTypes: [CIBA_GRANT, 'refresh_token']);
    $user = $this->makeUser('agent2@example.test');
    $ciba = app(BackchannelAuthentication::class);

    $result = $ciba->request($registered->client, ['openid'], $user->id);
    $ciba->approve($result->requestId, $user->id, 'org-1');

    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);

    $body = $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ])->assertOk()->json();

    expect($body['refresh_token'] ?? null)->toBeNull();
});
