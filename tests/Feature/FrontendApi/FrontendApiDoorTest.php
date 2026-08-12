<?php

declare(strict_types=1);

use Cbox\Id\FrontendApi\Contracts\PublishableKeys;
use Cbox\Id\FrontendApi\Enums\KeyMode;
use Cbox\Id\FrontendApi\FrontendApiServiceProvider;
use Cbox\Id\FrontendApi\Models\PublishableKey;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * THE ORIGIN IS THE CREDENTIAL, and these hold that.
 *
 * A publishable key is public by design — it ships in a JS bundle and is in the page
 * source of every customer who uses it. Nothing about that is a compromise, PROVIDED the
 * key is useless from anywhere its owner did not name. Every test here is a way that
 * property could be lost.
 */
// The flag is set and the provider re-booted, because the route group is decided in
// boot() — setting the flag alone would leave the routes unregistered and every assertion
// here would be about a 404. This mirrors an install that boots with the flag already on.
beforeEach(function (): void {
    $this->app['config']->set('cbox-id.frontend_api.enabled', true);

    // Re-register the provider now the flag is on, which is what a real install does at
    // boot with the flag already in its config.
    (new FrontendApiServiceProvider($this->app))->boot();
});

function issueKey(array $origins = ['https://app.acme.test']): PublishableKey
{
    return app(PublishableKeys::class)->issue('Test key', KeyMode::Test, $origins);
}

it('refuses a request with no key at all', function (): void {
    $this->getJson('/frontend/v1/config')->assertStatus(401);
});

it('refuses a key used from an origin nobody allow-listed', function (): void {
    $key = issueKey();

    $this->withHeaders([
        'X-Cbox-Publishable-Key' => $key->key,
        'Origin' => 'https://evil.test',
    ])->getJson('/frontend/v1/config')->assertStatus(401);
});

/**
 * THE CLASSIC, and the reason the comparison is byte-for-byte. A suffix match — the
 * shape everybody reaches for — lets an attacker register `acme.test.evil.test` and be
 * treated as `acme.test`.
 */
it('refuses an origin that merely ends with an allowed one', function (): void {
    $key = issueKey(['https://acme.test']);

    $this->withHeaders([
        'X-Cbox-Publishable-Key' => $key->key,
        'Origin' => 'https://acme.test.evil.test',
    ])->getJson('/frontend/v1/config')->assertStatus(401);
});

it('refuses a revoked key', function (): void {
    $key = issueKey();
    app(PublishableKeys::class)->revoke($key->id);

    $this->withHeaders([
        'X-Cbox-Publishable-Key' => $key->key,
        'Origin' => 'https://app.acme.test',
    ])->getJson('/frontend/v1/config')->assertStatus(401);
});

/**
 * An unknown key and a disallowed origin must be INDISTINGUISHABLE. Telling an anonymous
 * caller "that key is real, but not from here" confirms the key exists.
 */
it('answers an unknown key exactly as it answers a bad origin', function (): void {
    $key = issueKey();

    $unknown = $this->withHeaders([
        'X-Cbox-Publishable-Key' => 'pk_test_'.str_repeat('a', 32),
        'Origin' => 'https://app.acme.test',
    ])->getJson('/frontend/v1/config');

    $badOrigin = $this->withHeaders([
        'X-Cbox-Publishable-Key' => $key->key,
        'Origin' => 'https://evil.test',
    ])->getJson('/frontend/v1/config');

    expect($unknown->status())->toBe($badOrigin->status())
        ->and($unknown->json())->toBe($badOrigin->json());
});

/**
 * A REFUSAL CARRIES NO CORS HEADERS, which is the point and not an oversight: the browser
 * should see a CORS failure, because a page has no business reading the body of a
 * rejection it was not authorized to make.
 */
it('sends no CORS headers on a refusal', function (): void {
    $response = $this->withHeaders([
        'X-Cbox-Publishable-Key' => 'pk_test_'.str_repeat('a', 32),
        'Origin' => 'https://evil.test',
    ])->getJson('/frontend/v1/config');

    expect($response->headers->has('Access-Control-Allow-Origin'))->toBeFalse();
});

it('admits an allowed origin and echoes exactly that origin back', function (): void {
    $key = issueKey();

    $response = $this->withHeaders([
        'X-Cbox-Publishable-Key' => $key->key,
        'Origin' => 'https://app.acme.test',
    ])->getJson('/frontend/v1/config')->assertOk();

    expect($response->headers->get('Access-Control-Allow-Origin'))->toBe('https://app.acme.test')
        // Without `Vary`, a shared cache can hand one customer's allow-origin to another
        // customer's browser, and the second is refused for reasons nobody can reproduce.
        ->and($response->headers->get('Vary'))->toContain('Origin')
        ->and($response->headers->get('Access-Control-Allow-Credentials'))->toBe('true');
});

/**
 * THE PREFLIGHT A REAL BROWSER SENDS, which is the only one that matters.
 *
 * A browser never puts the value of a custom header on the preflight — it advertises the
 * NAME in `Access-Control-Request-Headers` and sends the value on the real request. A test
 * that helpfully includes `X-Cbox-Publishable-Key` on the OPTIONS is testing a request no
 * browser produces, which is how this door shipped refusing every genuine preflight and
 * therefore every cross-origin call in the product, with the suite green.
 */
it('answers the preflight a browser actually sends, with no key on it', function (): void {
    issueKey();

    $response = $this->call('OPTIONS', '/frontend/v1/config', [], [], [], [
        'HTTP_ORIGIN' => 'https://app.acme.test',
        'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'POST',
        'HTTP_ACCESS_CONTROL_REQUEST_HEADERS' => 'x-cbox-publishable-key, content-type',
    ]);

    expect($response->getStatusCode())->toBe(204)
        // A 204 with no headers is a refusal the browser cannot tell from a success —
        // the headers ARE the answer, so they are what this asserts.
        ->and($response->headers->get('Access-Control-Allow-Origin'))->toBe('https://app.acme.test')
        ->and($response->headers->get('Access-Control-Allow-Credentials'))->toBe('true')
        ->and($response->headers->get('Vary'))->toContain('Origin')
        ->and($response->headers->get('Access-Control-Allow-Headers'))->toContain('X-Cbox-Publishable-Key')
        // `/frontend/v1/session` reads a bearer token the page already holds. Without this
        // the endpoint is unreachable cross-origin however good the rest of the door is.
        ->and($response->headers->get('Access-Control-Allow-Headers'))->toContain('Authorization');
});

it('refuses a preflight from an origin no active key names', function (): void {
    issueKey(['https://app.acme.test']);

    $response = $this->call('OPTIONS', '/frontend/v1/config', [], [], [], [
        'HTTP_ORIGIN' => 'https://evil.test',
        'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'POST',
    ]);

    expect($response->getStatusCode())->toBe(401)
        ->and($response->headers->has('Access-Control-Allow-Origin'))->toBeFalse();
});

it('stops answering the preflight once the only key naming that origin is revoked', function (): void {
    $key = issueKey();
    app(PublishableKeys::class)->revoke($key->id);

    $this->call('OPTIONS', '/frontend/v1/config', [], [], [], [
        'HTTP_ORIGIN' => 'https://app.acme.test',
        'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'POST',
    ])->assertStatus(401);
});

/**
 * The preflight grants NOTHING. It is answered on the origin alone, so the thing that must
 * still hold is that the real request is not.
 */
it('still requires a key on the real request the preflight cleared', function (): void {
    issueKey();

    $this->withHeaders(['Origin' => 'https://app.acme.test'])
        ->getJson('/frontend/v1/config')
        ->assertStatus(401);
});

/**
 * ONE ENVIRONMENT CANNOT RESOLVE ANOTHER'S KEY.
 *
 * Every other test in this file runs inside a single pinned environment, so the scope that
 * enforces this is the one thing they cannot see — deleting it left the whole suite green
 * while a key minted by one customer answered for another's data.
 */
it('cannot resolve a key belonging to another environment', function (): void {
    $environments = app(EnvironmentContext::class);
    $keys = app(PublishableKeys::class);

    $theirs = $environments->runAs(
        GenericEnvironment::of('env_theirs'),
        fn (): PublishableKey => $keys->issue('Theirs', KeyMode::Test, ['https://app.acme.test']),
    );

    $resolved = $environments->runAs(
        GenericEnvironment::of('env_ours'),
        fn (): ?PublishableKey => $keys->resolve($theirs->key),
    );

    expect($resolved)->toBeNull();
});

it('will not answer a preflight for an origin only another environment allow-listed', function (): void {
    app(EnvironmentContext::class)->runAs(
        GenericEnvironment::of('env_theirs'),
        fn (): PublishableKey => app(PublishableKeys::class)->issue('Theirs', KeyMode::Test, ['https://theirs.test']),
    );

    $this->call('OPTIONS', '/frontend/v1/config', [], [], [], [
        'HTTP_ORIGIN' => 'https://theirs.test',
        'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'POST',
    ])->assertStatus(401);
});

it('serves nothing at all when the channel is switched off', function (): void {
    $key = issueKey();
    config()->set('cbox-id.frontend_api.enabled', false);

    // A fresh application picks the config up at boot, which is where the route group is
    // decided — the same thing that happens on an install that never turned it on.
    $this->refreshApplication();
    config()->set('cbox-id.frontend_api.enabled', false);

    $this->withHeaders([
        'X-Cbox-Publishable-Key' => $key->key,
        'Origin' => 'https://app.acme.test',
    ])->getJson('/frontend/v1/config')->assertNotFound();
});
