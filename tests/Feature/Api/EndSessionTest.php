<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Illuminate\Auth\GenericUser;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

const POST_LOGOUT_URI = 'https://rp.example/after-logout';

if (! function_exists('logoutClient')) {
    function logoutClient(): RegisteredClient
    {
        return app(ClientRegistry::class)->register(new NewClient(
            'RP with logout',
            ClientType::Confidential,
            redirectUris: ['https://rp.example/callback'],
            scopes: ['openid'],
            postLogoutRedirectUris: [POST_LOGOUT_URI],
        ));
    }
}

if (! function_exists('idTokenHint')) {
    /**
     * @param  array<string, mixed>  $overrides
     */
    function idTokenHint(string $clientId, array $overrides = []): string
    {
        return app(TokenSigner::class)->sign(array_merge([
            'sub' => 'alice',
            'aud' => $clientId,
            'iat' => time(),
            'exp' => time() + 3600,
        ], $overrides));
    }
}

it('advertises the end_session_endpoint in discovery', function (): void {
    $this->get('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('end_session_endpoint', fn (string $v): bool => str_ends_with($v, '/oauth/logout'));
});

it('redirects to a registered post_logout_redirect_uri and carries state', function (): void {
    $client = logoutClient();

    $this->get('/oauth/logout?'.http_build_query([
        'client_id' => $client->client->client_id,
        'post_logout_redirect_uri' => POST_LOGOUT_URI,
        'state' => 'xyz-123',
    ]))->assertRedirect(POST_LOGOUT_URI.'?state=xyz-123');
});

it('identifies the client from the id_token_hint audience (no explicit client_id)', function (): void {
    $client = logoutClient();

    $this->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => idTokenHint($client->client->client_id),
        'post_logout_redirect_uri' => POST_LOGOUT_URI,
    ]))->assertRedirect(POST_LOGOUT_URI);
});

it('refuses to redirect to an unregistered uri (no open redirect)', function (): void {
    $client = logoutClient();

    $this->get('/oauth/logout?'.http_build_query([
        'client_id' => $client->client->client_id,
        'post_logout_redirect_uri' => 'https://evil.example/steal',
    ]))->assertOk()->assertSee('signed out', false);
});

it('does not redirect when no client can be identified', function (): void {
    // A registered uri, but no client_id and no hint — nobody to check the allow-list against.
    logoutClient();

    $this->get('/oauth/logout?'.http_build_query([
        'post_logout_redirect_uri' => POST_LOGOUT_URI,
    ]))->assertOk();
});

it('ignores an unverifiable id_token_hint rather than trusting it', function (): void {
    $client = logoutClient();

    // A syntactically-plausible but unsigned/garbage hint must not identify the client.
    $this->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => 'not.a.real.jwt',
        'post_logout_redirect_uri' => POST_LOGOUT_URI,
    ]))->assertOk();
});

it('refuses to redirect when client_id contradicts the hint audience', function (): void {
    $client = logoutClient();
    $other = logoutClient();

    $this->get('/oauth/logout?'.http_build_query([
        'client_id' => $client->client->client_id,
        'id_token_hint' => idTokenHint($other->client->client_id),
        'post_logout_redirect_uri' => POST_LOGOUT_URI,
    ]))->assertOk();
});

it('revokes the authenticated subject sessions on logout', function (): void {
    $subject = $this->makeUser('alice@example.test');
    $sessions = app(SessionManager::class);
    $session = $sessions->start($subject->id, null, ['pwd']);

    expect($sessions->active($session->id))->not->toBeNull();

    // auth()->id() drives the teardown; authenticate the guard with the subject id.
    $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))->get('/oauth/logout')->assertOk();

    expect($sessions->active($session->id))->toBeNull();
});
