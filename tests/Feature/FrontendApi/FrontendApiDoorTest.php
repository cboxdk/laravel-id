<?php

declare(strict_types=1);

use Cbox\Id\FrontendApi\Contracts\PublishableKeys;
use Cbox\Id\FrontendApi\Enums\KeyMode;
use Cbox\Id\FrontendApi\FrontendApiServiceProvider;
use Cbox\Id\FrontendApi\Models\PublishableKey;
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

it('answers a preflight without requiring anything else', function (): void {
    $key = issueKey();

    $this->call('OPTIONS', '/frontend/v1/config', [], [], [], [
        'HTTP_X_CBOX_PUBLISHABLE_KEY' => $key->key,
        'HTTP_ORIGIN' => 'https://app.acme.test',
    ])->assertNoContent();
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
