<?php

declare(strict_types=1);

use Cbox\Id\FrontendApi\Contracts\FrontendConfigContributor;
use Cbox\Id\FrontendApi\Contracts\PublishableKeys;
use Cbox\Id\FrontendApi\Enums\KeyMode;
use Cbox\Id\FrontendApi\FrontendApiServiceProvider;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $this->app['config']->set('cbox-id.frontend_api.enabled', true);
    (new FrontendApiServiceProvider($this->app))->boot();

    $this->key = app(PublishableKeys::class)->issue('Site', KeyMode::Test, ['https://app.acme.test']);
});

/**
 * A real subject with a real access token — the shape a page holds after a sign-in.
 *
 * @return array{id: string, token: string, jti: string}
 */
function subjectWithLiveToken(): array
{
    $subject = app(Subjects::class)->create(email: 'ada@acme.test', name: 'Ada Lovelace');

    $issued = app(TokenIssuer::class)->issueForUser(
        test()->makeClient(['openid'])->client,
        $subject->id,
        null,
        ['openid'],
    );

    return ['id' => $subject->id, 'token' => $issued->token, 'jti' => $issued->jti];
}

function asBrowser(): array
{
    return [
        'X-Cbox-Publishable-Key' => test()->key->key,
        'Origin' => 'https://app.acme.test',
    ];
}

/**
 * The document that makes embedded UI possible: everything needed to DRAW a sign-in box,
 * and nothing that identifies anybody.
 */
it('gives a browser the endpoints and its own mode', function (): void {
    $this->withHeaders(asBrowser())->getJson('/frontend/v1/config')
        ->assertOk()
        ->assertJsonPath('mode', 'test')
        ->assertJsonStructure(['issuer', 'endpoints' => ['authorization', 'token', 'jwks'], 'social']);
});

/**
 * A CONTRIBUTOR ADDS TO THE DOCUMENT. It does not redefine it.
 *
 * The host registers these, and the host is trusted — but "trusted" is not the same as
 * "unconstrained". A contributor that returned its own `issuer` or `endpoints` would point
 * every embedded sign-in box in the product somewhere else, and the contract's promise
 * would be a docblock rather than a rule.
 */
it('lets a contributor add to the document but never overwrite it', function (): void {
    app()->bind('test-contributor', fn (): FrontendConfigContributor => new class implements FrontendConfigContributor
    {
        public function contribute(array $config): array
        {
            return ['issuer' => 'https://evil.test', 'endpoints' => [], 'appearance' => ['accent' => '#bada55']];
        }
    });
    app()->tag(['test-contributor'], FrontendConfigContributor::class);

    // The controller is resolved with its contributors at construction, so the tag has to
    // be in place before the request builds one.
    (new FrontendApiServiceProvider($this->app))->register();

    $body = $this->withHeaders(asBrowser())->getJson('/frontend/v1/config')->assertOk()->json();

    expect($body['issuer'])->not->toBe('https://evil.test')
        ->and($body['endpoints'])->not->toBe([])
        ->and($body['appearance'])->toBe(['accent' => '#bada55']);
});

/**
 * THE ENUMERATION ORACLE EVERY IDENTITY PRODUCT EVENTUALLY LEAKS, and a public endpoint
 * is the easiest place to leak it. Nothing here may be keyed on a person.
 */
it('answers the same to every caller, regardless of what they ask about', function (): void {
    $a = $this->withHeaders(asBrowser())->getJson('/frontend/v1/config?email=known@acme.test');
    $b = $this->withHeaders(asBrowser())->getJson('/frontend/v1/config?email=nobody@acme.test');

    expect($a->json())->toBe($b->json());
});

/**
 * A publishable key must teach a competitor nothing about the size or shape of the
 * customer's estate.
 */
it('leaks no counts, ids or private configuration', function (): void {
    $body = $this->withHeaders(asBrowser())->getJson('/frontend/v1/config')->json();
    $flat = json_encode($body) ?: '';

    foreach (['client_secret', 'config_encrypted', 'webhook', 'scim', 'organization_id', 'user_count'] as $forbidden) {
        expect($flat)->not->toContain($forbidden);
    }
});

/**
 * ONE URL, ONE ORIGIN, TWO KEYS — TWO DOCUMENTS.
 *
 * The door picks the environment from the KEY, not from the host, so a browser cache keyed
 * on the URL alone would serve one environment's configuration to a page holding the
 * other's key. `private` keeps shared caches out of it; the browser's own cache is the one
 * that had to be told.
 */
it('varies on the key as well as the origin', function (): void {
    $response = $this->withHeaders(asBrowser())->getJson('/frontend/v1/config')->assertOk();

    expect($response->headers->get('Vary'))->toContain('X-Cbox-Publishable-Key')
        ->and($response->headers->get('Vary'))->toContain('Origin');
});

it('is cached privately, never in a shared cache', function (): void {
    // The document differs per environment, and a shared cache keyed on the URL alone
    // would serve one customer's configuration to another customer's page.
    $response = $this->withHeaders(asBrowser())->getJson('/frontend/v1/config')->assertOk();

    expect($response->headers->get('Cache-Control'))->toContain('private');
});

/**
 * Signed out is a STATE, not an error. `<UserButton/>` renders on pages nobody has signed
 * in on, and making it treat 401 as a state is how flash-of-signed-out bugs are born.
 */
it('answers the session endpoint with a null user rather than a 401', function (): void {
    $this->withHeaders(asBrowser())->getJson('/frontend/v1/session')
        ->assertOk()
        ->assertJsonPath('user', null);
});

it('never caches who is signed in', function (): void {
    $response = $this->withHeaders(asBrowser())->getJson('/frontend/v1/session')->assertOk();

    expect($response->headers->get('Cache-Control'))->toContain('no-store');
});

/**
 * THE AUTHENTICATED BRANCH, which had no coverage at all — `return null` at the top of
 * `bearer()` used to leave the whole file green while every avatar in the product went
 * anonymous.
 */
it('names the person a live token belongs to, and nothing else about them', function (): void {
    $subject = subjectWithLiveToken();

    $this->withHeaders(asBrowser() + ['Authorization' => 'Bearer '.$subject['token']])
        ->getJson('/frontend/v1/session')
        ->assertOk()
        ->assertJsonPath('user.id', $subject['id'])
        ->assertJsonPath('user.email', 'ada@acme.test')
        // A label, an initial and an id. Anything else on a user record is either private
        // or somebody else's business, and a passthrough is how it leaks.
        ->assertJsonPath('user', fn (array $user): bool => array_keys($user) === ['id', 'email', 'name']);
});

it('goes back to anonymous the moment the token stops being live', function (): void {
    $subject = subjectWithLiveToken();

    app(TokenIntrospector::class)->revoke($subject['jti']);

    $this->withHeaders(asBrowser() + ['Authorization' => 'Bearer '.$subject['token']])
        ->getJson('/frontend/v1/session')
        ->assertOk()
        ->assertJsonPath('user', null);
});

/**
 * The publishable key names an environment and says a browser is asking. The TOKEN is the
 * entire authority — a page holding a key and somebody else's expired token learns nothing.
 */
it('refuses to answer a token it cannot introspect', function (): void {
    $this->withHeaders(asBrowser() + ['Authorization' => 'Bearer not-a-real-token'])
        ->getJson('/frontend/v1/session')
        ->assertOk()
        ->assertJsonPath('user', null);
});

/*
 * BEING FRIENDLIER ABOUT THE SHAPE OF THE ANSWER IS NOT LICENCE TO BE LAXER ABOUT WHO
 * GETS IT. This endpoint answers `{"user": null}` to a stranger on purpose — signed out
 * is a state, not an error — and for a while it read the bearer straight off the header
 * and asked nothing else of it. `/oauth/userinfo` next door asks three things: the token
 * must be audienced here, it must carry `openid`, and it must satisfy its own DPoP
 * binding. Every one of those was a way to turn a token minted for something else into
 * somebody's name and email address.
 *
 * These refusals are 401s and not `{"user": null}`: a rejected stolen token must not
 * render identically to a logged-out visitor, or it is invisible both to the integrator
 * debugging it and in the logs.
 */
it('refuses a token minted for somebody else\'s API', function (): void {
    $subject = app(Subjects::class)->create(email: 'ada@acme.test', name: 'Ada Lovelace');
    $issued = app(TokenIssuer::class)->issueForUser(
        $this->makeClient(['openid'])->client,
        $subject->id,
        null,
        ['openid'],
        // RFC 8707: minted for a customer's own resource server, which may hold it — and
        // must not be able to trade it for the identity of the person who granted it.
        'https://api.acme.test',
    );

    $this->withHeaders(asBrowser() + ['Authorization' => 'Bearer '.$issued->token])
        ->getJson('/frontend/v1/session')
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_token');
});

it('refuses a token that was never an identity token', function (): void {
    $subject = app(Subjects::class)->create(email: 'ada@acme.test', name: 'Ada Lovelace');
    $issued = app(TokenIssuer::class)->issueForUser(
        $this->makeClient(['api.read'])->client,
        $subject->id,
        null,
        // No `openid`. A pure API token was never granted the right to name its holder.
        ['api.read'],
    );

    $this->withHeaders(asBrowser() + ['Authorization' => 'Bearer '.$issued->token])
        ->getJson('/frontend/v1/session')
        ->assertStatus(401)
        ->assertJsonPath('error_description', 'the access token lacks the openid scope');
});

it('refuses a sender-constrained token presented without its proof', function (): void {
    $subject = app(Subjects::class)->create(email: 'ada@acme.test', name: 'Ada Lovelace');
    $issued = app(TokenIssuer::class)->issueForUser(
        $this->makeClient(['openid'])->client,
        $subject->id,
        null,
        ['openid'],
        null,
        // The client asked to be sender-constrained; the whole point is that the token
        // alone is worthless to a thief. This was the one door where it still worked.
        dpopJkt: 'a-thumbprint-nobody-can-prove',
    );

    $response = $this->withHeaders(asBrowser() + ['Authorization' => 'Bearer '.$issued->token])
        ->getJson('/frontend/v1/session')
        ->assertStatus(401);

    expect($response->headers->get('WWW-Authenticate'))->toStartWith('DPoP ');
});
