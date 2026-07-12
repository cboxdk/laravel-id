<?php

declare(strict_types=1);

namespace Cbox\Id\Api;

use Cbox\Id\Api\Http\Controllers\DiscoveryController;
use Cbox\Id\Api\Http\Controllers\HealthController;
use Cbox\Id\Api\Http\Controllers\IntrospectionController;
use Cbox\Id\Api\Http\Controllers\JwksController;
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
        Route::post('/oauth/introspect', IntrospectionController::class);
        Route::get('/up', HealthController::class);
    }
}
