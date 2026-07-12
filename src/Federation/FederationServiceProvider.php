<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Illuminate\Support\ServiceProvider;

final class FederationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Connections::class, ConnectionService::class);
        $this->app->singleton(FederationFlow::class, FederationLoginService::class);

        // AssertionValidator (SAML/OIDC signature validation, wrapping a vetted
        // library) is bound by the app once the per-type validators land.
    }
}
