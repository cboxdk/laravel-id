<?php

declare(strict_types=1);

namespace Cbox\Id\Api;

use Cbox\Id\Api\Http\Controllers\DiscoveryController;
use Cbox\Id\Api\Http\Controllers\HealthController;
use Cbox\Id\Api\Http\Controllers\IntrospectionController;
use Cbox\Id\Api\Http\Controllers\JwksController;
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
        // Machine-facing endpoints. The interactive OIDC authorize/token flow,
        // the SCIM HTTP surface, and the SAML ACS routes land here next, each
        // built against its conformance suite.
        Route::get('/.well-known/jwks.json', JwksController::class);
        Route::get('/.well-known/openid-configuration', DiscoveryController::class);
        Route::post('/oauth/token', TokenController::class);
        Route::post('/oauth/introspect', IntrospectionController::class);
        Route::get('/up', HealthController::class);

        // SAML ACS — unauthenticated; the assertion's XML signature is the auth.
        Route::post('/sso/saml/{connection}/acs', SamlAcsController::class);

        // SCIM 2.0 provisioning, authenticated by the directory bearer token.
        Route::middleware(AuthenticateScim::class)->prefix('scim/v2')->group(function (): void {
            Route::get('/Users', [UserController::class, 'index']);
            Route::post('/Users', [UserController::class, 'store']);
            Route::get('/Users/{id}', [UserController::class, 'show']);
            Route::put('/Users/{id}', [UserController::class, 'replace']);
            Route::patch('/Users/{id}', [UserController::class, 'patch']);
            Route::delete('/Users/{id}', [UserController::class, 'destroy']);
        });
    }
}
