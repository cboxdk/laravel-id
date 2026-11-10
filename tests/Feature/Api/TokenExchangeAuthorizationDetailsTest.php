<?php

declare(strict_types=1);

use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationEvent;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

/*
 * RFC 9396 authorization_details on an RFC 8693 token exchange: a client holding the
 * person's token narrows it to exactly one action, which the new token names, and only
 * with a type the client registered.
 */

uses(RefreshDatabase::class);

beforeEach(function (): void {
    User::query()->create(['id' => 'alice', 'email' => 'alice@rar.test', 'status' => UserStatus::Active]);
});

if (! function_exists('rarClaims')) {
    /** @return array<string, mixed> */
    function rarClaims(string $jwt): array
    {
        return (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', $jwt)[1]), true);
    }
}

/** @param list<string>|null $types */
function rarAllow(RegisteredClient $registered, ?array $types): RegisteredClient
{
    $registered->client->forceFill(['authorization_details_types' => $types])->save();

    return $registered;
}

/** @param array<string, mixed> $extra */
function rarExchange(object $test, RegisteredClient $registered, string $subjectToken, array $extra): TestResponse
{
    return $test->postJson('/oauth/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'subject_token' => $subjectToken,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        ...$extra,
    ]);
}

const RAR_PLAN = [['type' => 'cbox_infra_change', 'plan_digest' => 'sha256:0123456789abcdef', 'plan_id' => 'cpl_1']];

it('puts the authorization_details on the exchanged token and echoes them (RFC 9396 §7, §9.1)', function (): void {
    $org = $this->makeOrganization();
    $registered = rarAllow($this->makeClient(['openid', 'api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']), ['cbox_infra_change']);
    $authTime = time() - 30;
    $subject = app(TokenIssuer::class)->issueForAuthenticatedUser($registered->client, 'alice', $org->id, ['openid', 'api.read'], new AuthenticationEvent($authTime, ['pwd', 'mfa']))->token;

    $response = rarExchange($this, $registered, $subject, [
        'authorization_details' => json_encode(RAR_PLAN),
        'resource' => 'https://engine.example.test',
    ])->assertOk();

    expect($response->json('authorization_details'))->toBe(RAR_PLAN);

    $claims = rarClaims($response->json('access_token'));
    expect($claims['authorization_details'])->toBe(RAR_PLAN)
        ->and($claims['sub'])->toBe('alice')
        ->and($claims['org'])->toBe($org->id)
        // The subject token's own login, carried, never a newer one.
        ->and($claims['auth_time'])->toBe($authTime)
        ->and($claims['acr'])->toBe('urn:cbox-id:aal2')
        ->and((array) $claims['aud'])->toContain('https://engine.example.test');
});

it('accepts authorization_details sent as a JSON body array', function (): void {
    $org = $this->makeOrganization();
    $registered = rarAllow($this->makeClient(['openid', 'api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']), ['cbox_infra_change']);
    $subject = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read'])->token;

    $response = rarExchange($this, $registered, $subject, ['authorization_details' => RAR_PLAN])->assertOk();

    expect(rarClaims($response->json('access_token'))['authorization_details'])->toBe(RAR_PLAN)
        // No login facts on the subject: none invented on the new token.
        ->and(rarClaims($response->json('access_token')))->not->toHaveKey('auth_time');
});

it('refuses a type the client did not register', function (?array $types): void {
    $org = $this->makeOrganization();
    $registered = rarAllow($this->makeClient(['openid', 'api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']), $types);
    $subject = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read'])->token;

    rarExchange($this, $registered, $subject, ['authorization_details' => json_encode(RAR_PLAN)])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_authorization_details');
})->with([
    'no types registered' => [null],
    'another type registered' => [['payment_initiation']],
]);

it('refuses malformed authorization_details (RFC 9396 §5)', function (mixed $value): void {
    $org = $this->makeOrganization();
    $registered = rarAllow($this->makeClient(['openid', 'api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']), ['cbox_infra_change']);
    $subject = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read'])->token;

    rarExchange($this, $registered, $subject, ['authorization_details' => $value])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_authorization_details');
})->with([
    'not JSON' => ['{nope'],
    'an object, not an array' => [json_encode(['type' => 'cbox_infra_change'])],
    'an empty array' => ['[]'],
    'an entry without a type' => [json_encode([['plan_digest' => 'x']])],
    'a list as an entry' => [json_encode([['a', 'b']])],
    'a non-string type' => [json_encode([['type' => 7]])],
    'too many entries' => [json_encode(array_fill(0, 11, ['type' => 'cbox_infra_change']))],
    'too large' => [json_encode([['type' => 'cbox_infra_change', 'x' => str_repeat('a', 5000)]])],
    'nested too deep' => [json_encode([['type' => 'cbox_infra_change', 'a' => ['b' => ['c' => ['d' => ['e' => 1]]]]]])],
    'a null value' => [json_encode([['type' => 'cbox_infra_change', 'a' => null]])],
]);

it('leaves an exchange without authorization_details exactly as before', function (): void {
    $org = $this->makeOrganization();
    $registered = rarAllow($this->makeClient(['openid', 'api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']), ['cbox_infra_change']);
    $subject = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read'])->token;

    $response = rarExchange($this, $registered, $subject, [])->assertOk();

    expect($response->json())->not->toHaveKey('authorization_details')
        ->and(rarClaims($response->json('access_token')))->not->toHaveKey('authorization_details');
});
