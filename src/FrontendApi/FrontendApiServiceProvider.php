<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi;

use Cbox\Id\Api\Http\Middleware\ResolveEnvironment;
use Cbox\Id\FrontendApi\Contracts\FrontendConfigContributor;
use Cbox\Id\FrontendApi\Contracts\PublishableKeys;
use Cbox\Id\FrontendApi\Http\Controllers\ConfigController;
use Cbox\Id\FrontendApi\Http\Controllers\SessionController;
use Cbox\Id\FrontendApi\Http\Middleware\AuthenticateFrontendApi;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

/**
 * The browser-facing channel: a public key, an origin allow-list, and two documents.
 *
 * OFF BY DEFAULT. An install that has not thought about which origins may talk to it
 * should not be answering browsers, and a feature that quietly appears on upgrade is one
 * nobody reviewed. `cbox-id.frontend_api.enabled` turns it on.
 *
 * NOT UNDER THE API SURFACE MIDDLEWARE. Every other route group in this package carries
 * `surfaceMiddleware()` — the host's plane gate — and this one deliberately does not:
 * those gates answer "is this host an identity provider", and the Frontend API is
 * answered by whichever host the environment resolves on, to a browser that is not on
 * that host at all. Its gate is the origin allow-list, which is stricter and is the one
 * the customer configured.
 */
class FrontendApiServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(PublishableKeys::class, DatabasePublishableKeys::class);

        // Contributors are collected by tag so an application can add branding without
        // this package knowing what branding is. See FrontendConfigContributor.
        $this->app->bind(ConfigController::class, static function (Application $app): ConfigController {
            /** @var iterable<FrontendConfigContributor> $contributors */
            $contributors = $app->tagged(FrontendConfigContributor::class);

            return new ConfigController($contributors);
        });
    }

    public function boot(): void
    {
        if (config('cbox-id.frontend_api.enabled') !== true) {
            return;
        }

        Route::middleware([ResolveEnvironment::class, AuthenticateFrontendApi::class])
            ->prefix('frontend/v1')
            ->group(function (): void {
                // OPTIONS is matched explicitly on each route rather than left to a
                // catch-all: a preflight that 404s reads to a developer as CORS being
                // broken, when the real answer is that they typed the path wrong.
                Route::match(['get', 'options'], '/config', ConfigController::class);
                Route::match(['get', 'options'], '/session', SessionController::class);
            });
    }
}
