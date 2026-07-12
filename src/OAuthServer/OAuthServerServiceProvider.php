<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
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
        $this->app->singleton(AuthorizationCodes::class, AuthorizationCodeService::class);

        // The /oauth/token endpoint (authorization_code + PKCE, client_credentials)
        // lives in the Api layer. The browser consent screen lands with the SaaS app.
    }
}
