<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/*
 * The token endpoint is throttled per (client id, address) under a per-address ceiling.
 * Every service behind one egress address used to share one 30/min bucket; these hold
 * that they no longer do, and that the looser keying opens no new way to starve a client.
 *
 * The requests carry wrong secrets on purpose: the throttle runs before authentication,
 * so a refused request counts exactly like an accepted one, and anything but 429 means
 * the throttle let it through.
 */
beforeEach(function (): void {
    config([
        'cbox-id.oauth.token_rate_limits.per_client' => 3,
        'cbox-id.oauth.token_rate_limits.per_ip' => 8,
        'cbox-id.oauth.token_rate_limits.anonymous' => 2,
    ]);
});

function tokenRequestAs(string $clientId, string $address = '198.51.100.7'): TestResponse
{
    return test()->withServerVariables(['REMOTE_ADDR' => $address])->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $clientId,
        'client_secret' => 'wrong-secret',
    ]);
}

it('limits one client at its threshold', function (): void {
    foreach (range(1, 3) as $ignored) {
        expect(tokenRequestAs('client-a')->getStatusCode())->not->toBe(429);
    }

    tokenRequestAs('client-a')->assertStatus(429);
});

it('gives two clients on one address independent buckets', function (): void {
    foreach (range(1, 3) as $ignored) {
        tokenRequestAs('client-a');
    }
    tokenRequestAs('client-a')->assertStatus(429);

    expect(tokenRequestAs('client-b')->getStatusCode())->not->toBe(429);
});

it('still issues a token to one client while another on the same address is limited', function (): void {
    foreach (range(1, 4) as $ignored) {
        tokenRequestAs('client-a');
    }

    $registered = $this->makeClient(['api.read'], grantTypes: ['client_credentials']);

    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.7'])->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'api.read',
    ])->assertOk()->assertJsonStructure(['access_token']);
});

it('reads the client id from HTTP Basic as well as the body', function (): void {
    $basic = fn (string $clientId) => $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.7'])
        ->withHeader('Authorization', 'Basic '.base64_encode($clientId.':wrong-secret'))
        ->postJson('/oauth/token', ['grant_type' => 'client_credentials']);

    foreach (range(1, 3) as $ignored) {
        $basic('client-a');
    }
    $basic('client-a')->assertStatus(429);

    // Same client by the body: the same bucket.
    tokenRequestAs('client-a')->assertStatus(429);
    expect($basic('client-b')->getStatusCode())->not->toBe(429);
});

it('reads the client id from the sub of a client assertion', function (): void {
    $assertion = fn (string $clientId): string => implode('.', [
        Base64Url::encode('{"alg":"RS256"}'),
        Base64Url::encode((string) json_encode(['iss' => $clientId, 'sub' => $clientId])),
        Base64Url::encode('not-a-signature'),
    ]);
    $send = fn (string $clientId) => $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.7'])->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => $assertion($clientId),
    ]);

    foreach (range(1, 3) as $ignored) {
        $send('agent-a');
    }
    $send('agent-a')->assertStatus(429);
    tokenRequestAs('agent-a')->assertStatus(429);
    expect($send('agent-b')->getStatusCode())->not->toBe(429);
});

it('limits a request that names no client per address', function (): void {
    $anonymous = fn (string $address) => $this->withServerVariables(['REMOTE_ADDR' => $address])
        ->postJson('/oauth/token', ['grant_type' => 'client_credentials']);

    foreach (range(1, 2) as $ignored) {
        expect($anonymous('198.51.100.7')->getStatusCode())->not->toBe(429);
    }
    $anonymous('198.51.100.7')->assertStatus(429);

    expect($anonymous('203.0.113.9')->getStatusCode())->not->toBe(429);
});

it('holds every client on one address to the address ceiling', function (): void {
    foreach (range(1, 8) as $attempt) {
        expect(tokenRequestAs('invented-'.$attempt)->getStatusCode())->not->toBe(429);
    }

    tokenRequestAs('invented-9')->assertStatus(429);
    expect(tokenRequestAs('invented-9', '203.0.113.9')->getStatusCode())->not->toBe(429);
});

it('does not let another address exhaust a client by naming it', function (): void {
    foreach (range(1, 5) as $ignored) {
        tokenRequestAs('client-a', '203.0.113.66');
    }
    tokenRequestAs('client-a', '203.0.113.66')->assertStatus(429);

    expect(tokenRequestAs('client-a', '198.51.100.7')->getStatusCode())->not->toBe(429);
});
