<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\Facades\Route;

/**
 * THE CALLBACK MUST SURVIVE THE REAL MIDDLEWARE STACK.
 *
 * `POST /sso/oidc/{connection}/callback` is a cross-site form submission from the identity
 * provider's own origin — `response_mode=form_post`, which Apple chooses by itself the
 * moment a scope beyond `openid` is requested. It carries no Laravel CSRF token and never
 * could: the provider has no way to know one.
 *
 * ASSERTS ON THE REGISTRATION, NOT ON A REQUEST, and that is the whole point of this file.
 * `PreventRequestForgery::handle()` returns early under `runningUnitTests()`, so a test
 * that POSTs through Laravel's helpers passes whether the exemption works or not — which
 * is exactly what happened: the route was registered with
 * `withoutMiddleware(VerifyCsrfToken::class)`, that excluded nothing, and every federation
 * test stayed green while a real Apple callback would have answered 419.
 *
 * It excluded nothing because Laravel 13's `web` group holds `PreventRequestForgery`, of
 * which `VerifyCsrfToken` and `ValidateCsrfToken` are deprecated SUBCLASSES —
 * `Router::resolveMiddleware()` matches in one direction only, so excluding the child
 * leaves the parent in place. The name that has to appear below is therefore the PARENT's,
 * and asserting on it is what this test exists to do.
 */
it('excludes the CSRF middleware the framework actually installs, by its own name', function (): void {
    $route = collect(Route::getRoutes()->getRoutes())
        ->first(fn ($route): bool => $route->uri() === 'sso/oidc/{connection}/callback'
            && in_array('POST', $route->methods(), true));

    expect($route)->not->toBeNull('the callback must accept POST — a form_post answer is a POST');

    // `PreventRequestForgery` is what `Middleware::web()` puts in the group. An exclusion
    // naming only a subclass of it is a no-op, and the whole class of bug here is that
    // such a no-op is invisible from inside the test suite.
    expect($route->excludedMiddleware())->toContain(PreventRequestForgery::class);
});

/**
 * The exemption is one route wide. Every other browser-surface POST in the same group —
 * SAML's ACS and SLO, which are also cross-site — keeps whatever the host applies.
 */
it('exempts nothing else on the browser surface', function (): void {
    $others = collect(Route::getRoutes()->getRoutes())
        ->filter(fn ($route): bool => str_starts_with($route->uri(), 'sso/')
            && $route->uri() !== 'sso/oidc/{connection}/callback');

    expect($others)->not->toBeEmpty();

    foreach ($others as $route) {
        expect($route->excludedMiddleware())->not->toContain(PreventRequestForgery::class, $route->uri());
    }
});
