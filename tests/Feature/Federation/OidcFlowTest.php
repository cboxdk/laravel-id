<?php

declare(strict_types=1);

use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\Contracts\SessionManager;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

/**
 * @return array{private: string, public: string}
 */
function oidcFlowKeypair(): array
{
    $resource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    openssl_pkey_export($resource, $private);
    $public = openssl_pkey_get_details($resource)['key'];

    return ['private' => $private, 'public' => $public];
}

/**
 * The OIDC connection config (with a fresh keypair) — the connection itself is
 * created in each test via the protected $this->makeConnection helper.
 *
 * @return array{config: array<string, mixed>, private: string}
 */
function oidcFlowSetup(): array
{
    $keys = oidcFlowKeypair();

    return [
        'config' => [
            'issuer' => 'https://idp.corp',
            'client_id' => 'rp-client-123',
            'client_secret' => 'rp-secret',
            'authorization_endpoint' => 'https://idp.corp/authorize',
            'token_endpoint' => 'https://idp.corp/token',
            'signing_key' => $keys['public'],
        ],
        'private' => $keys['private'],
    ];
}

function oidcFlowIdToken(string $privatePem, string $nonce): string
{
    $now = time();

    return JWT::encode([
        'iss' => 'https://idp.corp',
        'aud' => 'rp-client-123',
        'sub' => 'idp-user-42',
        'email' => 'dana@corp.com',
        'name' => 'Dana Reeves',
        'nonce' => $nonce,
        'iat' => $now,
        'exp' => $now + 300,
    ], $privatePem, 'RS256');
}

it('redirects to the IdP authorize endpoint with state and nonce', function (): void {
    $setup = oidcFlowSetup();
    $connection = $this->makeConnection($this->makeOrganization()->id, ConnectionType::Oidc, 'Corp OIDC', $setup['config']);

    $response = $this->get('/sso/oidc/'.$connection->id.'/redirect');

    $response->assertRedirect();
    $location = $response->headers->get('Location');

    expect($location)->toStartWith('https://idp.corp/authorize?')
        ->and($location)->toContain('client_id=rp-client-123')
        ->and($location)->toContain('response_type=code')
        ->and($location)->toContain('nonce=');
});

it('completes login on a valid callback (code exchange + id_token + nonce)', function (): void {
    $setup = oidcFlowSetup();
    $connection = $this->makeConnection($this->makeOrganization()->id, ConnectionType::Oidc, 'Corp OIDC', $setup['config']);

    $state = 'state-abc';
    $nonce = 'nonce-xyz';
    Http::fake(['idp.corp/token' => Http::response(['id_token' => oidcFlowIdToken($setup['private'], $nonce)])]);

    $response = $this->withSession(['oidc.'.$connection->id => ['state' => $state, 'nonce' => $nonce]])
        ->get('/sso/oidc/'.$connection->id.'/callback?code=auth-code&state='.$state);

    $response->assertOk();
    $sessionId = $response->json('session_id');

    expect($sessionId)->toBeString()
        ->and(app(SessionManager::class)->active($sessionId))->not->toBeNull();
});

it('rejects a callback whose state does not match (CSRF)', function (): void {
    $setup = oidcFlowSetup();
    $connection = $this->makeConnection($this->makeOrganization()->id, ConnectionType::Oidc, 'Corp OIDC', $setup['config']);

    $this->withSession(['oidc.'.$connection->id => ['state' => 'real-state', 'nonce' => 'n']])
        ->get('/sso/oidc/'.$connection->id.'/callback?code=x&state=forged-state')
        ->assertStatus(400);
});

it('rejects a callback whose id_token nonce does not match (replay)', function (): void {
    $setup = oidcFlowSetup();
    $connection = $this->makeConnection($this->makeOrganization()->id, ConnectionType::Oidc, 'Corp OIDC', $setup['config']);

    Http::fake(['idp.corp/token' => Http::response(['id_token' => oidcFlowIdToken($setup['private'], 'a-different-nonce')])]);

    $this->withSession(['oidc.'.$connection->id => ['state' => 's', 'nonce' => 'expected-nonce']])
        ->get('/sso/oidc/'.$connection->id.'/callback?code=x&state=s')
        ->assertStatus(401);
});
