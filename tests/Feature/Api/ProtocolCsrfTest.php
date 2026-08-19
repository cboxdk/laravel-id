<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Route;

/**
 * @group security
 *
 * ROUTES THIS PACKAGE ADVERTISES MUST BE CALLABLE BY THE CLIENTS IT ADVERTISES THEM TO.
 *
 * The protocol endpoints that take a cross-site POST — SAML IdP SSO and SLO on the binding
 * our own published metadata prefers, RP-initiated logout, and the RFC 7591/7592
 * registration API — sat inside the `web` group with its CSRF middleware. None of their
 * callers can carry a Laravel session token: an SP posts a signed SAML message, a relying
 * party posts a logout form, a DCR client posts JSON with a bearer. Each got a 419 in HTML
 * from a route the discovery document told it to use.
 *
 * The reference console had these exemptions in its own bootstrap, so the only deployment
 * where it worked was ours. That is what makes this the package's problem to solve.
 *
 * ASSERTED ON THE ROUTE DEFINITION, not by sending a request: Laravel skips CSRF
 * verification under `runningUnitTests()`, so a request-level test passes whether the
 * middleware is there or not — which is exactly how this survived a full suite.
 */
function protocolRoute(string $uri, string $method): RoutingRoute
{
    foreach (Route::getRoutes()->getRoutes() as $route) {
        if ($route->uri() === $uri && in_array($method, $route->methods(), true)) {
            return $route;
        }
    }

    throw new RuntimeException("No {$method} route registered at /{$uri}");
}

it('exempts the protocol endpoints a tokenless client must reach', function (string $uri, string $method): void {
    $route = protocolRoute($uri, $method);

    expect($route->excludedMiddleware() ?? [])->toContain(PreventRequestForgery::class);
})->with([
    // Both bindings are advertised in the IdP metadata this package publishes; the POST
    // one is what Okta and ADFS choose.
    'saml idp sso' => ['sso/saml/idp/sso', 'POST'],
    'saml idp slo' => ['sso/saml/idp/slo', 'POST'],
    // The SP role's Single Logout takes the customer IdP's signed LogoutRequest.
    'saml sp slo' => ['sso/saml/{connection}/slo', 'POST'],
    // OIDC RP-Initiated Logout §5: POST is mandatory, and required when the
    // id_token_hint is too long for a URL.
    'rp-initiated logout' => ['oauth/logout', 'POST'],
    // RFC 7591 registration and RFC 7592 management, a back-channel JSON API.
    'dynamic registration' => ['oauth/register', 'POST'],
    // RFC 7592 §2.2 updates a registration with PUT, not POST.
    'registration management' => ['oauth/register/{client}', 'PUT'],
])->group('security');

/**
 * And the mirror, which is what keeps the exemption honest: nothing that authenticates by
 * an ambient session may join the list. A route that trusts the session cookie and skips
 * CSRF is precisely the request CSRF exists to stop.
 */
it('exempts nothing whose only credential is the session', function (): void {
    $exempt = [];

    foreach (Route::getRoutes()->getRoutes() as $route) {
        if (! in_array('POST', $route->methods(), true)) {
            continue;
        }

        if (in_array(PreventRequestForgery::class, $route->excludedMiddleware() ?? [], true)) {
            $exempt[] = $route->uri();
        }
    }

    // Every exempt route carries its own authentication INSIDE the request: an XML
    // signature, a bearer, a client assertion, a signed id_token_hint, or a `state` bound
    // to the browser by a single-use cookie. This package registers no session-guarded
    // POST at all, so any name appearing here that is not on this list is a new one, and
    // whoever added it owes an answer to "what authenticates this instead".
    expect($exempt)->toEqualCanonicalizing([
        'sso/oidc/{connection}/callback',
        'sso/saml/{connection}/slo',
        'sso/saml/idp/sso',
        'sso/saml/idp/slo',
        'oauth/logout',
        'oauth/register',
    ]);
})->group('security');
