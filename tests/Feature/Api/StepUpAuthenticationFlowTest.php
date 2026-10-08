<?php

declare(strict_types=1);

use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Crypto\ValueObjects\TokenClaims;
use Cbox\Id\OAuthServer\Contracts\AuthenticationAwareTokenIssuer;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Enums\AuthenticationContextClass;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Support\BearerChallenge;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationEvent;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationRequirement;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Cbox\Id\Tests\Fixtures\Actions\ForgeAuthenticationContextAction;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/*
 * RFC 9470 end to end, with the test standing in for the two pieces a host writes — the
 * `/authorize` screen and the resource server — using exactly the primitives they call:
 *
 *   resource server: token too weak → 401 insufficient_user_authentication (acr_values, max_age)
 *   client:          re-runs /authorize with those parameters
 *   /authorize:      AuthenticationRequirement::fromAuthorizationRequest() + assessSession()
 *                    → a password-only session is told to step up; an MFA one is issued a code
 *   token endpoint:  access token and id_token carry the ACHIEVED acr and the login's auth_time
 *   introspection:   returns both; a refresh keeps the original values
 */

const STEP_UP_VERIFIER = 'a-sufficiently-long-step-up-code-verifier-0123456789';

beforeEach(function (): void {
    // makeClient() is a protected TestCase method, so only a closure bound to the test
    // can call it.
    $this->stepUpClient = $this->makeClient(
        ['openid', 'offline_access', 'api.read'],
        ClientType::Confidential,
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    );
});

/** What a host's /authorize does once the person is signed in: the code, from the SESSION. */
function stepUpCode(RegisteredClient $client, Session $session, array $scopes = ['openid', 'offline_access', 'api.read']): string
{
    return app(AuthorizationCodes::class)->issue(
        $client->client->client_id,
        $session->user_id,
        null,
        'https://app.test/cb',
        $scopes,
        Base64Url::encode(hash('sha256', STEP_UP_VERIFIER, true)),
        'S256',
        'n-0S6_WzA2Mj',
        $session->created_at?->getTimestamp(),
        array_values($session->amr),
        sessionId: $session->id,
    );
}

function stepUpExchange(object $test, RegisteredClient $client, string $code): TestResponse
{
    return $test->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => STEP_UP_VERIFIER,
    ])->assertOk();
}

function stepUpClaims(string $jwt): TokenClaims
{
    return app(TokenSigner::class)->verify($jwt, [SigningAlg::RS256, SigningAlg::ES256, SigningAlg::EdDSA]);
}

/** The resource server: requires aal2 within five minutes, as RFC 9470 §3's example would. */
function stepUpResourceServer(string $accessToken): ?BearerChallenge
{
    $token = app(TokenIntrospector::class)->introspect($accessToken);

    expect($token->active)->toBeTrue();

    return AuthenticationRequirement::of(AuthenticationContextClass::Aal2, 300)->assessToken($token)->challenge();
}

it('runs the whole step-up loop: challenge, re-authorize, step up, satisfied token, refresh', function (): void {
    $client = $this->stepUpClient;
    $sessions = app(SessionManager::class);

    // 1. A password-only login gets an ordinary token…
    $password = $sessions->start('user_42', null, ['pwd']);
    $weak = stepUpExchange($this, $client, stepUpCode($client, $password));

    expect(stepUpClaims($weak->json('access_token'))->get('acr'))->toBe('urn:cbox-id:aal1');

    // 2. …which the resource server refuses with the RFC 9470 §3 challenge.
    $challenge = stepUpResourceServer($weak->json('access_token'));

    expect($challenge?->header())->toBe(
        'Bearer error="insufficient_user_authentication", '
        .'error_description="The requested authentication context (urn:cbox-id:aal2) was not met.", '
        .'acr_values="urn:cbox-id:aal2", max_age="300"',
    );

    // 3. The client re-runs /authorize with the challenge's acr_values and max_age (§4).
    $authorize = Request::create('/oauth/authorize', 'GET', [
        'response_type' => 'code',
        'client_id' => $client->client->client_id,
        'acr_values' => implode(' ', $challenge->acrValues),
        'max_age' => (string) $challenge->maxAge,
    ]);
    $requirement = AuthenticationRequirement::fromAuthorizationRequest($authorize);

    // 4. The host's /authorize: the password-only session must step up, not be issued a code.
    $assessment = $requirement->assessSession($password);

    expect($assessment->requiresStepUp())->toBeTrue()
        ->and($assessment->requiresReauthentication())->toBeFalse()
        ->and($assessment->authorizationError())->toBe('unmet_authentication_requirements');

    // 5. The person adds a second factor; the new session satisfies the request.
    $stepped = $sessions->start('user_42', null, ['pwd', 'mfa']);

    expect($requirement->assessSession($stepped)->isSatisfied())->toBeTrue();

    $tokens = stepUpExchange($this, $client, stepUpCode($client, $stepped));
    $authTime = $stepped->created_at?->getTimestamp();

    // 6. Both tokens describe the login that happened (RFC 9470 §6.1, OIDC Core §3.1.2.1:
    //    max_age was requested, so the id_token MUST carry auth_time).
    $access = stepUpClaims($tokens->json('access_token'));
    $id = stepUpClaims($tokens->json('id_token'));

    expect($access->get('acr'))->toBe('urn:cbox-id:aal2')
        ->and($access->get('auth_time'))->toBe($authTime)
        ->and($id->get('acr'))->toBe('urn:cbox-id:aal2')
        ->and($id->get('auth_time'))->toBe($authTime)
        ->and(ServerMetadata::document()['acr_values_supported'])->toContain($access->get('acr'));

    // 7. The resource server is now satisfied.
    expect(stepUpResourceServer($tokens->json('access_token')))->toBeNull();

    // 8. Introspection reports the same two facts (RFC 9470 §6.2).
    $this->postJson('/oauth/introspect', [
        'token' => $tokens->json('access_token'),
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
    ])->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonPath('acr', 'urn:cbox-id:aal2')
        ->assertJsonPath('auth_time', $authTime);

    // 9. A refresh keeps the ORIGINAL login's values (RFC 9470 §6.1) — so an hour on, the
    //    resource server's max_age refuses the refreshed token and asks for a fresh login.
    //    The hour is passed as the assessment's clock rather than travelled to: the token
    //    must still be live to be introspected at all.
    $refreshed = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'refresh_token' => $tokens->json('refresh_token'),
    ])->assertOk();

    $renewed = stepUpClaims($refreshed->json('access_token'));

    expect($renewed->get('acr'))->toBe('urn:cbox-id:aal2')
        ->and($renewed->get('auth_time'))->toBe($authTime)
        ->and(stepUpClaims($refreshed->json('id_token'))->get('auth_time'))->toBe($authTime);

    $introspected = app(TokenIntrospector::class)->introspect($refreshed->json('access_token'));
    $anHourLater = $authTime + 3600;

    expect($introspected->active)->toBeTrue();

    $stale = AuthenticationRequirement::of(AuthenticationContextClass::Aal2, 300)->assessToken($introspected, $anHourLater);

    expect($stale->requiresReauthentication())->toBeTrue()
        ->and($stale->requiresStepUp())->toBeFalse()
        ->and($stale->challenge()?->header())->toContain('max_age="300"');

    // …and the same session is now too old for /authorize as well: re-authenticate.
    expect($requirement->assessSession($stepped, $anHourLater)->authorizationError())->toBe('login_required');
});

it('stamps no acr or auth_time on a client_credentials token, nor reports them on introspection', function (): void {
    $client = $this->stepUpClient;

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'scope' => 'api.read',
    ])->assertOk();

    $claims = stepUpClaims($response->json('access_token'))->all();

    expect($claims)->not->toHaveKey('acr')->not->toHaveKey('auth_time');

    $this->postJson('/oauth/introspect', [
        'token' => $response->json('access_token'),
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
    ])->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonMissingPath('acr')
        ->assertJsonMissingPath('auth_time');
});

it('never lets a token-minting hook vouch for a second factor or a fresh sign-in', function (): void {
    config()->set('cbox-id.external_actions.hooks.token_minting', [ForgeAuthenticationContextAction::class]);
    $client = $this->stepUpClient->client;
    $issuer = app(TokenIssuer::class);

    expect($issuer)->toBeInstanceOf(AuthenticationAwareTokenIssuer::class);

    $claims = stepUpClaims($issuer->issueForAuthenticatedUser($client, 'alice', null, ['openid'], new AuthenticationEvent(1_800_000_000, ['pwd']))->token);

    expect($claims->get('acr'))->toBe('urn:cbox-id:aal1')
        ->and($claims->get('auth_time'))->toBe(1_800_000_000)
        ->and($claims->get('tenant_tier'))->toBe('pro');

    // And a token with no authentication behind it does not gain one from the hook.
    $bare = stepUpClaims($issuer->issueForUser($client, 'alice', null, ['openid'])->token)->all();

    expect($bare)->not->toHaveKey('acr')->not->toHaveKey('auth_time');
});

it('refuses a malformed max_age at the PAR endpoint as invalid_request', function (): void {
    $client = $this->stepUpClient;

    $push = fn (array $extra): TestResponse => $this->postJson('/oauth/par', [
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'response_type' => 'code',
        'redirect_uri' => 'https://app.test/cb',
        'scope' => 'openid',
        'code_challenge' => Base64Url::encode(hash('sha256', STEP_UP_VERIFIER, true)),
        'code_challenge_method' => 'S256',
        ...$extra,
    ]);

    $push(['max_age' => '-1'])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request')
        ->assertJsonPath('error_description', 'max_age must be a non-negative integer number of seconds.');

    $push(['max_age' => 'soon'])->assertStatus(400)->assertJsonPath('error', 'invalid_request');

    $push(['max_age' => '0', 'acr_values' => 'urn:cbox-id:aal2'])->assertCreated();
});
