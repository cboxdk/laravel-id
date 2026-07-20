<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\ClientAssertion\ClientAssertionValidator;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Contracts\ClientAssertion;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Contracts\DynamicClientRegistration;
use Cbox\Id\OAuthServer\Contracts\EndSession;
use Cbox\Id\OAuthServer\Contracts\PushedAuthorizationRequests;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Contracts\ServiceAccounts;
use Cbox\Id\OAuthServer\Contracts\TokenExchange;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Illuminate\Support\ServiceProvider;

class OAuthServerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ClientRegistry::class, ClientRegistryService::class);
        $this->app->singleton(ServiceAccounts::class, ServiceAccountService::class);
        $this->app->singleton(TokenIssuer::class, JwtTokenIssuer::class);

        // Access-token lifetime is operator-tunable. A short TTL is the standard way
        // stateless roles/permissions claims stay fresh — the token self-expires
        // rather than requiring a per-request revocation check.
        $this->app->when(JwtTokenIssuer::class)
            ->needs('$accessTokenTtl')
            ->give(static fn (): int => is_numeric($ttl = config('cbox-id.oauth.access_token_ttl', 900)) ? (int) $ttl : 900);
        $this->app->singleton(TokenIntrospector::class, JwtTokenIntrospector::class);
        $this->app->singleton(TokenExchange::class, TokenExchangeService::class);
        $this->app->singleton(AuthorizationCodes::class, AuthorizationCodeService::class);
        $this->app->singleton(DynamicClientRegistration::class, DynamicClientRegistrar::class);
        $this->app->singleton(RefreshTokens::class, RefreshTokenService::class);
        $this->app->singleton(PushedAuthorizationRequests::class, PushedAuthorizationService::class);
        $this->app->singleton(DeviceAuthorization::class, DeviceAuthorizationService::class);
        $this->app->singleton(BackchannelAuthentication::class, CibaAuthenticationService::class);
        $this->app->singleton(EndSession::class, EndSessionService::class);
        $this->app->singleton(ClientAssertion::class, ClientAssertionValidator::class);

        // The /oauth/token endpoint (authorization_code + PKCE, client_credentials)
        // lives in the Api layer. The browser consent screen lands with the SaaS app.
    }
}
