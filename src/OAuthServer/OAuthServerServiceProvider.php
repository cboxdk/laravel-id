<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\ServiceAccounts;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Illuminate\Support\ServiceProvider;

final class OAuthServerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ClientRegistry::class, ClientRegistryService::class);
        $this->app->singleton(ServiceAccounts::class, ServiceAccountService::class);
        $this->app->singleton(TokenIssuer::class, JwtTokenIssuer::class);
        $this->app->singleton(TokenIntrospector::class, JwtTokenIntrospector::class);

        // Interactive authorization-code / OIDC provider flow (browser consent, PKCE,
        // id_token, discovery, userinfo) lands in the Api layer on league/oauth2-server.
    }
}
