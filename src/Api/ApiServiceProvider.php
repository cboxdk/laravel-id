<?php

declare(strict_types=1);

namespace Cbox\Id\Api;

use Cbox\Id\Api\Http\Controllers\AuthorizationServerMetadataController;
use Cbox\Id\Api\Http\Controllers\DiscoveryController;
use Cbox\Id\Api\Http\Controllers\HealthController;
use Cbox\Id\Api\Http\Controllers\IntrospectionController;
use Cbox\Id\Api\Http\Controllers\JwksController;
use Cbox\Id\Api\Http\Controllers\ProtectedResourceMetadataController;
use Cbox\Id\Api\Http\Controllers\PushedAuthorizationController;
use Cbox\Id\Api\Http\Controllers\RegisteredClientController;
use Cbox\Id\Api\Http\Controllers\RegistrationController;
use Cbox\Id\Api\Http\Controllers\RevocationController;
use Cbox\Id\Api\Http\Controllers\Scim\DiscoveryController as ScimDiscoveryController;
use Cbox\Id\Api\Http\Controllers\Scim\GroupController;
use Cbox\Id\Api\Http\Controllers\Scim\UserController;
use Cbox\Id\Api\Http\Controllers\Sso\OidcCallbackController;
use Cbox\Id\Api\Http\Controllers\Sso\OidcRedirectController;
use Cbox\Id\Api\Http\Controllers\Sso\SamlAcsController;
use Cbox\Id\Api\Http\Controllers\Sso\SamlLoginController;
use Cbox\Id\Api\Http\Controllers\Sso\SamlLogoutController;
use Cbox\Id\Api\Http\Controllers\Sso\SamlMetadataController;
use Cbox\Id\Api\Http\Controllers\TokenController;
use Cbox\Id\Api\Http\Controllers\UserInfoController;
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
            // RFC 8414 + RFC 9728 — the metadata MCP clients discover the server by.
            Route::get('/.well-known/oauth-authorization-server', AuthorizationServerMetadataController::class);
            Route::get('/.well-known/oauth-protected-resource', ProtectedResourceMetadataController::class);
            Route::get('/up', HealthController::class);

            // SP SAML metadata for a connection — public, no secrets, imported by
            // the IdP admin during connector setup.
            Route::get('/sso/saml/{connection}/metadata', SamlMetadataController::class);
        });

        // UserInfo (OIDC §5.3) — bearer-authenticated, called per session.
        Route::middleware('throttle:120,1')->match(['get', 'post'], '/oauth/userinfo', UserInfoController::class);

        // Credential-bearing endpoints — throttled to blunt secret/token brute
        // force (secrets are 256-bit, so this is a backstop, not the only guard).
        Route::middleware('throttle:30,1')->group(function (): void {
            Route::post('/oauth/token', TokenController::class);
            Route::post('/oauth/introspect', IntrospectionController::class);
            Route::post('/oauth/revoke', RevocationController::class);

            // RFC 9126: back-channel pushed authorization requests.
            Route::post('/oauth/par', PushedAuthorizationController::class);

            // SAML ACS — unauthenticated; the assertion's XML signature is the auth.
            Route::post('/sso/saml/{connection}/acs', SamlAcsController::class);
        });

        // OIDC (RP-initiated) login — browser redirect flow, so it needs a session
        // for the state/nonce. The id_token signature + nonce are the auth.
        Route::middleware(['web', 'throttle:30,1'])->group(function (): void {
            Route::get('/sso/oidc/{connection}/redirect', OidcRedirectController::class);
            Route::get('/sso/oidc/{connection}/callback', OidcCallbackController::class);

            // SP-initiated SAML login (AuthnRequest) — needs a session for the
            // InResponseTo request id. Single Logout accepts the IdP's redirect
            // (GET) and, for some IdPs, POST.
            Route::get('/sso/saml/{connection}/login', SamlLoginController::class);
            Route::match(['get', 'post'], '/sso/saml/{connection}/slo', SamlLogoutController::class);

            // Dynamic Client Registration (RFC 7591) + management (RFC 7592). The
            // controller enforces the configured mode (disabled/protected/open).
            Route::post('/oauth/register', RegistrationController::class);
            Route::get('/oauth/register/{client}', [RegisteredClientController::class, 'show']);
            Route::put('/oauth/register/{client}', [RegisteredClientController::class, 'update']);
            Route::delete('/oauth/register/{client}', [RegisteredClientController::class, 'destroy']);
        });

        // SCIM 2.0 provisioning, authenticated by the directory bearer token.
        Route::middleware(['throttle:120,1', AuthenticateScim::class])->prefix('scim/v2')->group(function (): void {
            // Discovery (RFC 7644 §4) — connectors probe these during setup.
            Route::get('/ServiceProviderConfig', [ScimDiscoveryController::class, 'serviceProviderConfig']);
            Route::get('/ResourceTypes', [ScimDiscoveryController::class, 'resourceTypes']);
            Route::get('/Schemas', [ScimDiscoveryController::class, 'schemas']);

            Route::get('/Users', [UserController::class, 'index']);
            Route::post('/Users', [UserController::class, 'store']);
            Route::get('/Users/{id}', [UserController::class, 'show']);
            Route::put('/Users/{id}', [UserController::class, 'replace']);
            Route::patch('/Users/{id}', [UserController::class, 'patch']);
            Route::delete('/Users/{id}', [UserController::class, 'destroy']);

            Route::get('/Groups', [GroupController::class, 'index']);
            Route::post('/Groups', [GroupController::class, 'store']);
            Route::get('/Groups/{id}', [GroupController::class, 'show']);
            Route::put('/Groups/{id}', [GroupController::class, 'replace']);
            Route::patch('/Groups/{id}', [GroupController::class, 'patch']);
            Route::delete('/Groups/{id}', [GroupController::class, 'destroy']);
        });
    }
}
