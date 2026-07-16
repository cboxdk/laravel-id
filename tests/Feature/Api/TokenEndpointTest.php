<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Enums\ClientType;
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
    $registered = $this->makeClient(['openid', 'profile'], ClientType::Public);
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

it('carries the org name in the id_token, access token and userinfo', function (): void {
    $org = $this->makeOrganization('Northwind Traders');
    $registered = $this->makeClient(['openid', 'profile'], ClientType::Public);
    $verifier = 'a-sufficiently-long-code-verifier-1234567890';
    $challenge = Base64Url::encode(hash('sha256', $verifier, true));

    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user_42',
        $org->id,
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
    ])->assertOk();

    // id_token names the org.
    $idClaims = app(TokenSigner::class)->verify($response->json('id_token'), [SigningAlg::RS256]);
    expect($idClaims->get('org'))->toBe($org->id)
        ->and($idClaims->get('org_name'))->toBe('Northwind Traders');

    // Access token names the org.
    $accessClaims = app(TokenSigner::class)->verify($response->json('access_token'), [SigningAlg::RS256]);
    expect($accessClaims->get('org_name'))->toBe('Northwind Traders');

    // UserInfo resolves and returns it too.
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$response->json('access_token')])
        ->assertOk()
        ->assertJsonPath('org', $org->id)
        ->assertJsonPath('org_name', 'Northwind Traders');
});

it('echoes the OIDC nonce from the authorize request into the id_token', function (): void {
    $registered = $this->makeClient(['openid'], ClientType::Public);
    $verifier = 'a-sufficiently-long-code-verifier-1234567890';
    $challenge = Base64Url::encode(hash('sha256', $verifier, true));

    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user_42',
        'org_a',
        'https://app.test/cb',
        ['openid'],
        $challenge,
        'S256',
        'n-0S6_WzA2Mj', // the nonce
    );

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify($response->json('id_token'), [SigningAlg::RS256]);
    expect($claims->get('nonce'))->toBe('n-0S6_WzA2Mj');
});

it('omits nonce from the id_token when the authorize request had none', function (): void {
    $registered = $this->makeClient(['openid'], ClientType::Public);
    $verifier = 'a-sufficiently-long-code-verifier-1234567890';
    $challenge = Base64Url::encode(hash('sha256', $verifier, true));

    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user_42',
        'org_a',
        'https://app.test/cb',
        ['openid'],
        $challenge,
    );

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
    ])->assertOk();

    $claims = app(TokenSigner::class)->verify($response->json('id_token'), [SigningAlg::RS256]);
    expect($claims->get('nonce'))->toBeNull();
});

it('rejects the authorization_code grant with a bad PKCE verifier', function (): void {
    $registered = $this->makeClient(['openid'], ClientType::Public);
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

it('requires a confidential client to present its secret on authorization_code', function (): void {
    $registered = $this->makeClient(['openid'], ClientType::Confidential);
    $verifier = 'a-sufficiently-long-code-verifier-1234567890';
    $challenge = Base64Url::encode(hash('sha256', $verifier, true));

    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user_42',
        'org_a',
        'https://app.test/cb',
        ['openid'],
        $challenge,
    );

    // Valid code + valid PKCE, but no client_secret — a stolen code from a public
    // channel must not be exchangeable without the confidential client's secret.
    $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
    ])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

it('authenticates a confidential client via HTTP Basic (client_secret_basic)', function (): void {
    $registered = $this->makeClient(['api.read']);

    // RFC 6749 §2.3.1: credentials in the Authorization header, not the body.
    $this->withBasicAuth($registered->client->client_id, $registered->secret)
        ->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'scope' => 'api.read',
        ])
        ->assertOk()
        ->assertJsonPath('token_type', 'Bearer')
        ->assertJsonStructure(['access_token', 'expires_in']);
});

it('rejects combining HTTP Basic and body client credentials (RFC 6749 §2.3.1)', function (): void {
    $registered = $this->makeClient(['api.read']);

    // A client MUST NOT use more than one authentication mechanism per request.
    $this->withBasicAuth($registered->client->client_id, $registered->secret)
        ->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $registered->client->client_id,
            'client_secret' => $registered->secret,
            'scope' => 'api.read',
        ])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

it('accepts a confidential client on authorization_code with the correct secret', function (): void {
    $registered = $this->makeClient(['openid'], ClientType::Confidential);
    $verifier = 'a-sufficiently-long-code-verifier-1234567890';
    $challenge = Base64Url::encode(hash('sha256', $verifier, true));

    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        'user_42',
        'org_a',
        'https://app.test/cb',
        ['openid'],
        $challenge,
    );

    $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
    ])->assertOk()->assertJsonStructure(['access_token', 'id_token']);
});
