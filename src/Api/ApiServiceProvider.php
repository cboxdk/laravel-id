<?php

declare(strict_types=1);

namespace Cbox\Id\Api;

use Cbox\Id\Api\Http\Controllers\DiscoveryController;
use Cbox\Id\Api\Http\Controllers\HealthController;
use Cbox\Id\Api\Http\Controllers\IntrospectionController;
use Cbox\Id\Api\Http\Controllers\JwksController;
use Cbox\Id\Api\Http\Controllers\RegisteredClientController;
use Cbox\Id\Api\Http\Controllers\RegistrationController;
use Cbox\Id\Api\Http\Controllers\Scim\UserController;
use Cbox\Id\Api\Http\Controllers\Sso\SamlAcsController;
use Cbox\Id\Api\Http\Controllers\TokenController;
use Cbox\Id\Api\Http\Middleware\AuthenticateScim;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

final class ApiServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // Public metadata — cheap, cacheable, generously throttled.
        Route::middleware('throttle:300,1')->group(function (): void {
            Route::get('/.well-known/jwks.json', JwksController::class);
            Route::get('/.well-known/openid-configuration', DiscoveryController::class);
            Route::get('/up', HealthController::class);
        });

        // Credential-bearing endpoints — throttled to blunt secret/token brute
        // force (secrets are 256-bit, so this is a backstop, not the only guard).
        Route::middleware('throttle:30,1')->group(function (): void {
            Route::post('/oauth/token', TokenController::class);
            Route::post('/oauth/introspect', IntrospectionController::class);

            // SAML ACS — unauthenticated; the assertion's XML signature is the auth.
            Route::post('/sso/saml/{connection}/acs', SamlAcsController::class);

            // Dynamic Client Registration (RFC 7591) + management (RFC 7592). The
            // controller enforces the configured mode (disabled/protected/open).
            Route::post('/oauth/register', RegistrationController::class);
            Route::get('/oauth/register/{client}', [RegisteredClientController::class, 'show']);
            Route::put('/oauth/register/{client}', [RegisteredClientController::class, 'update']);
            Route::delete('/oauth/register/{client}', [RegisteredClientController::class, 'destroy']);
        });

        // SCIM 2.0 provisioning, authenticated by the directory bearer token.
        Route::middleware(['throttle:120,1', AuthenticateScim::class])->prefix('scim/v2')->group(function (): void {
            Route::get('/Users', [UserController::class, 'index']);
            Route::post('/Users', [UserController::class, 'store']);
            Route::get('/Users/{id}', [UserController::class, 'show']);
            Route::put('/Users/{id}', [UserController::class, 'replace']);
            Route::patch('/Users/{id}', [UserController::class, 'patch']);
            Route::delete('/Users/{id}', [UserController::class, 'destroy']);
        });
    }
}
