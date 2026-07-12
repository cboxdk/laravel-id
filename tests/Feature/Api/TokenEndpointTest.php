<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('issues an access token via client_credentials', function (): void {
    $registered = $this->makeClient(['api.read', 'api.write']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'api.read',
    ])
        ->assertOk()
        ->assertJsonPath('token_type', 'Bearer')
        ->assertJsonStructure(['access_token', 'expires_in']);
});

it('rejects client_credentials with a bad secret', function (): void {
    $registered = $this->makeClient(['api.read']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => 'wrong-secret',
    ])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

it('completes the authorization_code + PKCE flow and returns an id_token', function (): void {
    $registered = $this->makeClient(['openid', 'profile']);
    $verifier = 'a-sufficiently-long-code-verifier-1234567890';
    $challenge = Base64Url::encode(hash('sha256', $verifier, true));

    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user_42',
        'org_a',
        'https://app.test/cb',
        ['openid', 'profile'],
        $challenge,
    );

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
    ])
        ->assertOk()
        ->assertJsonStructure(['access_token', 'id_token', 'token_type', 'expires_in']);

    $idToken = $response->json('id_token');
    expect($idToken)->toBeString();

    $claims = app(TokenSigner::class)->verify($idToken, [SigningAlg::RS256]);
    expect($claims->get('sub'))->toBe('user_42')
        ->and($claims->get('aud'))->toBe($registered->client->client_id)
        ->and($claims->get('org'))->toBe('org_a');
});

it('rejects the authorization_code grant with a bad PKCE verifier', function (): void {
    $registered = $this->makeClient(['openid']);
    $verifier = 'a-sufficiently-long-code-verifier-1234567890';
    $challenge = Base64Url::encode(hash('sha256', $verifier, true));

    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user_42',
        null,
        'https://app.test/cb',
        ['openid'],
        $challenge,
    );

    $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => 'the-wrong-verifier',
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');
});

it('rejects an unsupported grant_type', function (): void {
    $this->postJson('/oauth/token', ['grant_type' => 'password'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'unsupported_grant_type');
});
