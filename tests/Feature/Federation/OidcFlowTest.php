<?php

declare(strict_types=1);

use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\Contracts\SessionManager;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

// The flow tests use fake IdP hostnames that don't resolve; the SSRF guard is
// exercised by its own test below, so disable enforcement for the happy paths
// (mirrors how the webhook delivery tests disable verify_url).
beforeEach(fn () => config(['cbox-id.federation.verify_url' => false]));

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

it('refuses a code exchange whose token_endpoint resolves to an internal address (SSRF)', function (): void {
    // The guard is on for this test; a token_endpoint pointing at the cloud
    // metadata service must be refused before any request leaves the box.
    config(['cbox-id.federation.verify_url' => true]);

    $setup = oidcFlowSetup();
    $setup['config']['token_endpoint'] = 'http://169.254.169.254/token';
    $connection = $this->makeConnection($this->makeOrganization()->id, ConnectionType::Oidc, 'Corp OIDC', $setup['config']);

    // If the guard were bypassed the request would hit the (unfaked) network; it
    // must instead be rejected as a failed exchange (401), never dispatched.
    Http::fake(['169.254.169.254/*' => Http::response(['id_token' => 'should-never-be-requested'])]);

    $this->withSession(['oidc.'.$connection->id => ['state' => 's', 'nonce' => 'n']])
        ->get('/sso/oidc/'.$connection->id.'/callback?code=x&state=s')
        ->assertStatus(401);

    Http::assertNothingSent();
});

it('rejects a callback whose id_token nonce does not match (replay)', function (): void {
    $setup = oidcFlowSetup();
    $connection = $this->makeConnection($this->makeOrganization()->id, ConnectionType::Oidc, 'Corp OIDC', $setup['config']);

    Http::fake(['idp.corp/token' => Http::response(['id_token' => oidcFlowIdToken($setup['private'], 'a-different-nonce')])]);

    $this->withSession(['oidc.'.$connection->id => ['state' => 's', 'nonce' => 'expected-nonce']])
        ->get('/sso/oidc/'.$connection->id.'/callback?code=x&state=s')
        ->assertStatus(401);
});

/**
 * THE CROSS-SITE POST, which is how Apple answers and how nothing else does.
 *
 * `response_mode=form_post` means the provider hands the browser an auto-submitting form
 * aimed at the redirect URI. Two things then break that a GET never exposes: the route
 * must accept POST at all, and the framework's CSRF token cannot be there — a provider
 * has no way to know it. `state` is what proves the answer belongs to this browser, and
 * it is checked exactly as it is on the GET.
 */
it('completes login on a form_post callback', function (): void {
    $setup = oidcFlowSetup();
    $connection = $this->makeConnection($this->makeOrganization()->id, ConnectionType::Oidc, 'Corp OIDC', $setup['config']);

    $state = 'state-posted';
    $nonce = 'nonce-posted';
    Http::fake(['idp.corp/token' => Http::response(['id_token' => oidcFlowIdToken($setup['private'], $nonce)])]);

    $response = $this->withSession(['oidc.'.$connection->id => ['state' => $state, 'nonce' => $nonce]])
        ->post('/sso/oidc/'.$connection->id.'/callback', ['code' => 'auth-code', 'state' => $state]);

    $response->assertOk();

    expect(app(SessionManager::class)->active((string) $response->json('session_id')))->not->toBeNull();
});

it('rejects a form_post callback whose state does not match (CSRF)', function (): void {
    $setup = oidcFlowSetup();
    $connection = $this->makeConnection($this->makeOrganization()->id, ConnectionType::Oidc, 'Corp OIDC', $setup['config']);

    $this->withSession(['oidc.'.$connection->id => ['state' => 'real-state', 'nonce' => 'n']])
        ->post('/sso/oidc/'.$connection->id.'/callback', ['code' => 'x', 'state' => 'forged-state'])
        ->assertStatus(400);
});

/**
 * AND WITHOUT A SESSION AT ALL, which is the actual condition on Apple's POST: a
 * `SameSite=Lax` session cookie is not sent on a cross-site POST, so the callback runs
 * against an empty session. The dedicated `SameSite=None` cookie is the only reason the
 * state survives — without it every Apple sign-in ends on "that link has expired".
 */
it('completes a form_post callback carrying no session, on the flow cookie alone', function (): void {
    $setup = oidcFlowSetup();
    $connection = $this->makeConnection($this->makeOrganization()->id, ConnectionType::Oidc, 'Corp OIDC', $setup['config']);

    // The redirect leg writes both. Read the cookie off that response rather than
    // building one by hand: a test that mints its own would still pass if the redirect
    // stopped setting it.
    $started = $this->get('/sso/oidc/'.$connection->id.'/redirect');
    $cookie = collect($started->headers->getCookies())
        ->first(fn ($c): bool => str_starts_with($c->getName(), 'cbox_fed_'));

    expect($cookie)->not->toBeNull()
        ->and($cookie->getSameSite())->toBe('none')
        ->and($cookie->isSecure())->toBeTrue()
        ->and($cookie->isHttpOnly())->toBeTrue();

    $location = (string) $started->headers->get('Location');
    parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

    Http::fake(['idp.corp/token' => Http::response([
        'id_token' => oidcFlowIdToken($setup['private'], (string) $query['nonce']),
    ])]);

    // A FRESH BROWSER STATE: no session, only the flow cookie — exactly what arrives
    // when the provider POSTs the callback from its own origin.
    $response = $this->flushSession()
        ->withUnencryptedCookie($cookie->getName(), (string) $cookie->getValue())
        ->post('/sso/oidc/'.$connection->id.'/callback', [
            'code' => 'auth-code',
            'state' => (string) $query['state'],
        ]);

    $response->assertOk();

    expect(app(SessionManager::class)->active((string) $response->json('session_id')))->not->toBeNull();
});

/**
 * The guard is only a guard where it is CALLED. A connection stored before
 * {@see BrowserStartUrl} existed still redirects through this controller, so the check
 * lives on the read path and this test drives the whole route rather than the helper.
 */
it('will not send a browser to a plaintext authorization endpoint', function (): void {
    $setup = oidcFlowSetup();
    $setup['config']['authorization_endpoint'] = 'http://idp.corp/authorize';
    $connection = $this->makeConnection($this->makeOrganization()->id, ConnectionType::Oidc, 'Corp OIDC', $setup['config']);

    $response = $this->get('/sso/oidc/'.$connection->id.'/redirect');

    // 502, not a 500: reachable by anybody who clicks the organization's sign-in button.
    $response->assertStatus(502);
    expect($response->headers->get('Location'))->toBeNull();
})->group('security');
