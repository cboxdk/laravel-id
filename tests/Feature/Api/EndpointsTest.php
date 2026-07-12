<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('serves the JWK Set', function (): void {
    $this->getJson('/.well-known/jwks.json')
        ->assertOk()
        ->assertJsonStructure(['keys']);
});

it('serves the OIDC discovery document', function (): void {
    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonStructure(['issuer', 'jwks_uri', 'token_endpoint', 'introspection_endpoint'])
        ->assertJsonPath('id_token_signing_alg_values_supported.0', 'RS256')
        ->assertJsonPath('code_challenge_methods_supported.0', 'S256');
});

it('introspects an active token over HTTP for an authenticated caller', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);

    $this->postJson('/oauth/introspect', [
        'token' => $token->token,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])
        ->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonPath('sub', $registered->client->client_id)
        ->assertJsonPath('scope', 'api.read');
});

it('accepts HTTP Basic client authentication on introspection', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);

    $this->postJson('/oauth/introspect', ['token' => $token->token], [
        'Authorization' => 'Basic '.base64_encode($registered->client->client_id.':'.$registered->secret),
    ])
        ->assertOk()
        ->assertJsonPath('active', true);
});

it('refuses introspection from an unauthenticated caller', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);

    // No client credentials — the endpoint must not act as an open token oracle.
    $this->postJson('/oauth/introspect', ['token' => $token->token])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

it('refuses introspection with a wrong client secret', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);

    $this->postJson('/oauth/introspect', [
        'token' => $token->token,
        'client_id' => $registered->client->client_id,
        'client_secret' => 'wrong-secret',
    ])->assertStatus(401);
});

it('reports a bad token as inactive for an authenticated caller', function (): void {
    $registered = $this->makeClient(['api.read']);

    $this->postJson('/oauth/introspect', [
        'token' => 'garbage',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])
        ->assertOk()
        ->assertJsonPath('active', false);
});

it('responds to the health probe', function (): void {
    $this->getJson('/up')->assertOk();
});
