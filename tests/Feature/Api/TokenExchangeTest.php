<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

if (! function_exists('txClaims')) {
    /**
     * @return array<string, mixed>
     */
    function txClaims(string $jwt): array
    {
        return (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', $jwt)[1]), true);
    }
}

const TX_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const TX_ACCESS = 'urn:ietf:params:oauth:token-type:access_token';

it('exchanges a subject token for a down-scoped access token (RFC 8693)', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['api.read', 'api.write'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']);
    $subjectToken = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read', 'api.write'])->token;

    $response = $this->postJson('/oauth/token', [
        'grant_type' => TX_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'subject_token' => $subjectToken,
        'subject_token_type' => TX_ACCESS,
        'scope' => 'api.read',
    ]);

    $response->assertOk()
        ->assertJsonPath('issued_token_type', TX_ACCESS)
        ->assertJsonPath('token_type', 'Bearer');

    // The new token is for the same subject, down-scoped to just api.read.
    $claims = txClaims($response->json('access_token'));
    expect($claims['sub'])->toBe('alice')
        ->and($claims['scope'])->toBe('api.read');
});

it('echoes the granted scope in the response (RFC 8693 §2.2.1)', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['api.read', 'api.write'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']);
    $subjectToken = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read', 'api.write'])->token;

    // Empty scope request → inherits the subject scopes → scope MUST be echoed.
    $this->postJson('/oauth/token', [
        'grant_type' => TX_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'subject_token' => $subjectToken,
        'subject_token_type' => TX_ACCESS,
    ])->assertOk()->assertJsonPath('scope', 'api.read api.write');
});

it('refuses to exchange a token that was not issued to (nor names) the calling client', function (): void {
    $org = $this->makeOrganization();
    $appA = $this->makeClient(['api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']);
    $appB = $this->makeClient(['api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']);
    // A user token minted for app A; app B must not be able to launder it.
    $subjectToken = app(TokenIssuer::class)->issueForUser($appA->client, 'alice', $org->id, ['api.read'])->token;

    $this->postJson('/oauth/token', [
        'grant_type' => TX_GRANT,
        'client_id' => $appB->client->client_id,
        'client_secret' => $appB->secret,
        'subject_token' => $subjectToken,
        'subject_token_type' => TX_ACCESS,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('rejects an unsupported requested_token_type', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']);
    $subjectToken = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read'])->token;

    $this->postJson('/oauth/token', [
        'grant_type' => TX_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'subject_token' => $subjectToken,
        'subject_token_type' => TX_ACCESS,
        'requested_token_type' => 'urn:ietf:params:oauth:token-type:refresh_token',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
});

it('rejects a malformed resource indicator (invalid_target)', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']);
    $subjectToken = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read'])->token;

    $this->postJson('/oauth/token', [
        'grant_type' => TX_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'subject_token' => $subjectToken,
        'subject_token_type' => TX_ACCESS,
        'resource' => 'not-an-absolute-uri',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');
});

it('refuses to WIDEN scope in an exchange (down-scope only)', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['api.read', 'api.write'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']);
    $subjectToken = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read'])->token;

    $this->postJson('/oauth/token', [
        'grant_type' => TX_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'subject_token' => $subjectToken,
        'subject_token_type' => TX_ACCESS,
        'scope' => 'api.write', // not present on the subject token
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_scope');
});

it('refuses an inactive / unknown subject token', function (): void {
    $registered = $this->makeClient(['api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']);

    $this->postJson('/oauth/token', [
        'grant_type' => TX_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'subject_token' => 'not-a-real-token',
        'subject_token_type' => TX_ACCESS,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('refuses an unsupported subject_token_type', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']);
    $subjectToken = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read'])->token;

    $this->postJson('/oauth/token', [
        'grant_type' => TX_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'subject_token' => $subjectToken,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:id_token',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
});

it('requires client authentication for token exchange', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']);
    $subjectToken = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read'])->token;

    $this->postJson('/oauth/token', [
        'grant_type' => TX_GRANT,
        'client_id' => $registered->client->client_id,
        // no client_secret
        'subject_token' => $subjectToken,
        'subject_token_type' => TX_ACCESS,
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('advertises token-exchange in discovery', function (): void {
    $grants = $this->getJson('/.well-known/openid-configuration')->assertOk()->json('grant_types_supported');
    expect($grants)->toContain(TX_GRANT);
});
