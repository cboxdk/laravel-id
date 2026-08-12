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

it('honors an EXPIRED id_token_hint (identity, not liveness — OIDC RP-logout §4)', function (): void {
    $client = logoutClient();

    // id_tokens live ~15 min; a real logout usually happens after expiry. The hint
    // must still identify the client so the RP gets its post-logout redirect.
    $this->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => idTokenHint($client->client->client_id, ['iat' => time() - 7200, 'exp' => time() - 3600]),
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

// Dropping the redirect is the right call, but a five-word page told integrators
// nothing. Under app.debug the response names the reason; in production it stays bare.
it('explains a dropped post_logout_redirect_uri under app.debug only', function (): void {
    logoutClient();

    config(['app.debug' => true]);
    $this->get('/oauth/logout?'.http_build_query([
        'post_logout_redirect_uri' => POST_LOGOUT_URI,
    ]))->assertOk()->assertSee('identified no client', false);

    config(['app.debug' => false]);
    $response = $this->get('/oauth/logout?'.http_build_query([
        'post_logout_redirect_uri' => POST_LOGOUT_URI,
    ]))->assertOk();

    expect($response->getContent())->toBe('You are signed out.');
});

it('names the allow-list as the reason when the client WAS identified', function (): void {
    $client = logoutClient();
    config(['app.debug' => true]);

    $this->get('/oauth/logout?'.http_build_query([
        'client_id' => $client->client->client_id,
        'post_logout_redirect_uri' => 'https://rp.example/not-registered',
    ]))->assertOk()->assertSee('not on that client', false);
});

it('says nothing extra when the RP asked for no redirect at all', function (): void {
    config(['app.debug' => true]);

    $response = $this->get('/oauth/logout')->assertOk();

    expect($response->getContent())->toBe('You are signed out.');
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

/**
 * GLOBAL SIGN-OUT NEEDS A VERIFIED `id_token_hint`, and that is not a formality.
 *
 * This endpoint is unauthenticated by design — a relying party reaches it by redirecting
 * the browser — and it answers GET. So without proof of WHICH End-User the request
 * concerns, "revoke every session this browser's owner holds" is a thing any page on the
 * internet can cause by sending the victim through a link: a denial of service against
 * every user of every deployment, mints nothing, needs no credential.
 *
 * The hint is the proof. `EndSessionService` verifies it against this server's own keys
 * and returns its `sub`; the teardown fires only when that names the person actually
 * holding the browser.
 */
it('revokes every session when a verified id_token_hint names the signed-in subject', function (): void {
    $client = logoutClient();
    $subject = $this->makeUser('alice@example.test');
    $sessions = app(SessionManager::class);
    $session = $sessions->start($subject->id, null, ['pwd']);

    expect($sessions->active($session->id))->not->toBeNull();

    $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->get('/oauth/logout?'.http_build_query([
            'client_id' => $client->client->client_id,
            'id_token_hint' => idTokenHint($client->client->client_id, ['sub' => $subject->id]),
        ]))->assertOk();

    expect($sessions->active($session->id))->toBeNull();
});

it('signs out only this browser when the request cannot say who it is about', function (): void {
    $subject = $this->makeUser('bob@example.test');
    $sessions = app(SessionManager::class);
    $session = $sessions->start($subject->id, null, ['pwd']);

    // No hint: the browser is signed out (the session cookie is cleared) and the person's
    // other devices are left alone. This is the shape a forged cross-site navigation
    // takes, and it used to revoke everything.
    $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->get('/oauth/logout')->assertOk();

    expect($sessions->active($session->id))->not->toBeNull();
})->group('security');

/**
 * And a hint naming somebody ELSE revokes nothing — the two ids are compared, so a valid
 * token minted for another subject cannot be used to sign that subject out.
 */
it('ignores a verified hint that names a different subject', function (): void {
    $client = logoutClient();
    $subject = $this->makeUser('carol@example.test');
    $sessions = app(SessionManager::class);
    $session = $sessions->start($subject->id, null, ['pwd']);

    $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->get('/oauth/logout?'.http_build_query([
            'client_id' => $client->client->client_id,
            'id_token_hint' => idTokenHint($client->client->client_id, ['sub' => 'somebody-else']),
        ]))->assertOk();

    expect($sessions->active($session->id))->not->toBeNull();
})->group('security');
