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
