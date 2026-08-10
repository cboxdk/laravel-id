<?php

declare(strict_types=1);

use Cbox\Id\FrontendApi\Contracts\PublishableKeys;
use Cbox\Id\FrontendApi\Enums\KeyMode;
use Cbox\Id\FrontendApi\FrontendApiServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $this->app['config']->set('cbox-id.frontend_api.enabled', true);
    (new FrontendApiServiceProvider($this->app))->boot();

    $this->key = app(PublishableKeys::class)->issue('Site', KeyMode::Test, ['https://app.acme.test']);
});

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
