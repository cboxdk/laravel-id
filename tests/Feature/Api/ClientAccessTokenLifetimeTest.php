<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Cbox\Id\OAuthServer\Models\DeviceCode;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/**
 * A client's own access-token lifetime reaches the token it is handed on EVERY grant —
 * user grants and machine grants alike — and never exceeds the configured ceiling.
 *
 * Each grant mints through the same issuer today, which is exactly why this walks all
 * six: the day one of them grows its own minting path, this is what notices.
 */
const TTL_VERIFIER = 'a-sufficiently-long-code-verifier-for-ttl-0123456789';

function ttlClient(int $ttl): RegisteredClient
{
    return app(ClientRegistry::class)->register(new NewClient(
        name: 'Every grant',
        redirectUris: ['https://app.test/cb'],
        grantTypes: [
            'client_credentials',
            'authorization_code',
            'refresh_token',
            'urn:ietf:params:oauth:grant-type:device_code',
            'urn:openid:params:grant-type:ciba',
            'urn:ietf:params:oauth:grant-type:token-exchange',
        ],
        scopes: ['openid', 'offline_access', 'api.read'],
        accessTokenTtl: $ttl,
    ));
}

function ttlOf(TestResponse $response): int
{
    $response->assertOk();

    $claims = app(TokenSigner::class)->verify((string) $response->json('access_token'), [SigningAlg::RS256]);
    $lifetime = $claims->get('exp') - $claims->get('iat');

    // The response, the signed claim and the revocation record must all say the same.
    expect($response->json('expires_in'))->toBe($lifetime);

    $record = AccessToken::query()->where('jti', $claims->get('jti'))->firstOrFail();
    expect(abs($record->expires_at->getTimestamp() - $claims->get('exp')))->toBeLessThanOrEqual(1);

    return $lifetime;
}

/**
 * @return array<string, mixed>
 */
function ttlCredentials(RegisteredClient $registered): array
{
    return ['client_id' => $registered->client->client_id, 'client_secret' => (string) $registered->secret];
}

function ttlAuthorizationCode(object $test, RegisteredClient $registered): TestResponse
{
    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user_ttl',
        'org_ttl',
        'https://app.test/cb',
        ['openid', 'offline_access'],
        Base64Url::encode(hash('sha256', TTL_VERIFIER, true)),
        'S256',
        null,
        1_700_000_000,
        ['pwd'],
    );

    return $test->postJson('/oauth/token', ttlCredentials($registered) + [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => TTL_VERIFIER,
    ]);
}

it('honours the client TTL on client_credentials', function (): void {
    $registered = ttlClient(300);

    expect(ttlOf($this->postJson('/oauth/token', ttlCredentials($registered) + ['grant_type' => 'client_credentials'])))->toBe(300);
});

it('honours the client TTL on authorization_code, for the access and the ID token', function (): void {
    $registered = ttlClient(300);
    $response = ttlAuthorizationCode($this, $registered);

    $id = app(TokenSigner::class)->verify((string) $response->json('id_token'), [SigningAlg::RS256]);

    expect(ttlOf($response))->toBe(300)
        ->and($id->get('exp') - $id->get('iat'))->toBe(300);
});

it('honours the client TTL on refresh_token', function (): void {
    $registered = ttlClient(300);
    $refresh = (string) ttlAuthorizationCode($this, $registered)->json('refresh_token');

    expect(ttlOf($this->postJson('/oauth/token', ttlCredentials($registered) + [
        'grant_type' => 'refresh_token',
        'refresh_token' => $refresh,
    ])))->toBe(300);
});

it('honours the client TTL on the device grant', function (): void {
    $registered = ttlClient(300);
    $device = app(DeviceAuthorization::class);
    $result = $device->request($registered->client, ['openid']);
    $device->approve($result->userCode, 'user_ttl', 'org_ttl');
    DeviceCode::query()->update(['last_polled_at' => now()->subMinute()]);

    expect(ttlOf($this->postJson('/oauth/token', ttlCredentials($registered) + [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
        'device_code' => $result->deviceCode,
    ])))->toBe(300);
});

it('honours the client TTL on CIBA', function (): void {
    $registered = ttlClient(300);
    $user = $this->makeUser('ttl@example.test');
    $ciba = app(BackchannelAuthentication::class);
    $result = $ciba->request($registered->client, ['openid'], $user->id);
    $ciba->approve($result->requestId, $user->id, 'org_ttl');
    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);

    expect(ttlOf($this->postJson('/oauth/token', ttlCredentials($registered) + [
        'grant_type' => 'urn:openid:params:grant-type:ciba',
        'auth_req_id' => $result->authReqId,
    ])))->toBe(300);
});

it('honours the client TTL on token exchange', function (): void {
    $org = $this->makeOrganization();
    $registered = ttlClient(300);
    $subject = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read'])->token;

    expect(ttlOf($this->postJson('/oauth/token', ttlCredentials($registered) + [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token' => $subject,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
    ])))->toBe(300);
});

/**
 * An operator who lowers the ceiling shortens every client already above it on the next
 * token — not only clients registered afterwards, which would leave the long-lived ones,
 * the ones the change was for, exactly as they were.
 */
it('clamps a client TTL above a lowered ceiling at minting', function (): void {
    $registered = ttlClient(7200);

    config()->set('cbox-id.oauth.max_access_token_ttl', 1800);

    expect(ttlOf($this->postJson('/oauth/token', ttlCredentials($registered) + ['grant_type' => 'client_credentials'])))->toBe(1800);

    $id = app(TokenSigner::class)->verify((string) ttlAuthorizationCode($this, $registered)->json('id_token'), [SigningAlg::RS256]);
    expect($id->get('exp') - $id->get('iat'))->toBe(1800);
});

it('leaves a client without its own TTL on the deployment default', function (): void {
    $registered = app(ClientRegistry::class)->register(new NewClient(name: 'Default', scopes: ['api.read']));

    expect(ttlOf($this->postJson('/oauth/token', ttlCredentials($registered) + ['grant_type' => 'client_credentials'])))->toBe(900);
});
