<?php

declare(strict_types=1);

use Cbox\Id\Api\ApiServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

/**
 * Re-register the package's protocol routes with a different surface gate.
 *
 * Routes are registered in the provider's boot(), which has already run by the time a
 * test body executes — so the config has to be set and the provider booted again. A
 * second registration of the same method+URI REPLACES the first in the route
 * collection, so this leaves exactly the routes the new configuration produces.
 *
 * @param  list<string>  $middleware
 */
function registerIdpSurface(array $middleware): void
{
    config(['cbox-id.api.middleware' => $middleware]);

    (new ApiServiceProvider(app()))->boot();
}

/**
 * The middleware actually applied to a registered route, by method + URI.
 *
 * @return list<string>
 */
function middlewareFor(string $method, string $uri): array
{
    foreach (Route::getRoutes()->getRoutes() as $route) {
        if ($route->uri() === $uri && in_array($method, $route->methods(), true)) {
            return array_values(array_filter($route->gatherMiddleware(), 'is_string'));
        }
    }

    return [];
}

it('serves the whole IdP surface on every host by default', function (): void {
    // The published default is EMPTY — a single-tenant / self-hosted deployment is one
    // host that IS the identity provider, and it must need no configuration to serve.
    expect(config('cbox-id.api.middleware'))->toBe([]);

    $this->getJson('/.well-known/openid-configuration')->assertOk();
    $this->getJson('/.well-known/jwks.json')->assertOk();
});

it('lets the host 404 the entire IdP surface with its own gate', function (): void {
    // A stand-in for the host's own "is this host an identity provider?" middleware.
    // The package deliberately has no opinion on the question — it only applies what
    // the host names.
    Route::aliasMiddleware('not-an-idp', fn ($request, $next) => abort(404));

    registerIdpSurface(['not-an-idp']);

    $this->getJson('/.well-known/openid-configuration')->assertNotFound();
    $this->getJson('/.well-known/jwks.json')->assertNotFound();
    $this->getJson('/.well-known/oauth-authorization-server')->assertNotFound();
    $this->getJson('/.well-known/oauth-protected-resource')->assertNotFound();
    $this->postJson('/oauth/token')->assertNotFound();
    $this->postJson('/oauth/par')->assertNotFound();
    $this->getJson('/sso/saml/idp/metadata')->assertNotFound();
    $this->getJson('/scim/v2/ServiceProviderConfig')->assertNotFound();
});

/**
 * The gate answers "may this host act as an ISSUER?" — not "may it federate?".
 *
 * INBOUND federation is this server as the RELYING party, and a host that is not an
 * issuer still legitimately does it: a multi-tenant platform's account/root host resolves
 * the account org's connection, sends the member to `/sso/oidc/{c}/redirect` on the host
 * they are already on, and the assertion has to come back there. Gating these 404'd the
 * entry point, the callback and the SP metadata an IdP admin imports to set the
 * connection up at all — locking an account whose org requires SSO out of its own
 * workspace. The connection's environment scope is the real boundary, on every host.
 */
it('does not gate inbound federation entry, callbacks or SP metadata', function (): void {
    Route::aliasMiddleware('issuer-only', fn ($request, $next) => abort(404));

    registerIdpSurface(['issuer-only']);

    // The issuer surface is gated...
    expect(middlewareFor('GET', '.well-known/openid-configuration'))->toContain('issuer-only')
        ->and(middlewareFor('GET', 'oauth/userinfo'))->toContain('issuer-only')
        ->and(middlewareFor('POST', 'oauth/token'))->toContain('issuer-only')
        ->and(middlewareFor('GET', 'scim/v2/Users'))->toContain('issuer-only')
        // ...including the IdP-ROLE SAML endpoints, which ARE issuer surface.
        ->and(middlewareFor('GET', 'sso/saml/idp/metadata'))->toContain('issuer-only')
        ->and(middlewareFor('GET', 'sso/saml/idp/sso'))->toContain('issuer-only');

    // ...and the RP half is not. Asserted on the route's middleware rather than on a
    // response code because these controllers answer an unknown connection id with their
    // own 404 — indistinguishable from the gate's, which is exactly the confusion that
    // let the regression through.
    foreach ([
        ['GET', 'sso/saml/{connection}/metadata'],
        ['GET', 'sso/saml/{connection}/login'],
        ['POST', 'sso/saml/{connection}/acs'],
        ['POST', 'sso/saml/{connection}/slo'],
        ['GET', 'sso/oidc/{connection}/redirect'],
        ['GET', 'sso/oidc/{connection}/callback'],
    ] as [$method, $uri]) {
        expect(middlewareFor($method, $uri))->not->toBeEmpty()
            ->and(middlewareFor($method, $uri))->not->toContain('issuer-only');
    }
});

it('never gates the liveness probe', function (): void {
    // A kubelet probes the POD, so the Host header maps to no environment and the gate
    // would refuse it — restarting healthy pods. /up sits outside the group on purpose.
    Route::aliasMiddleware('not-an-idp-either', fn ($request, $next) => abort(404));

    registerIdpSurface(['not-an-idp-either']);

    $this->getJson('/up')->assertOk()->assertExactJson(['status' => 'ok']);
});

it('ignores malformed middleware entries rather than handing them to the router', function (): void {
    registerIdpSurface([]);
    config(['cbox-id.api.middleware' => ['', 42, null]]);

    (new ApiServiceProvider(app()))->boot();

    $this->getJson('/.well-known/openid-configuration')->assertOk();
});
