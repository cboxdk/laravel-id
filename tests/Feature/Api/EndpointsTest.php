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

it('introspects an active token over HTTP', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);

    $this->postJson('/oauth/introspect', ['token' => $token->token])
        ->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonPath('sub', $registered->client->client_id)
        ->assertJsonPath('scope', 'api.read');
});

it('reports a bad token as inactive over HTTP', function (): void {
    $this->postJson('/oauth/introspect', ['token' => 'garbage'])
        ->assertOk()
        ->assertJsonPath('active', false);
});

it('responds to the health probe', function (): void {
    $this->getJson('/up')->assertOk();
});
