<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp;

use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\Contracts\SamlIdentityProvider;
use Cbox\Id\SamlIdp\Contracts\SamlSingleLogout;
use Cbox\Id\SamlIdp\Contracts\ServiceProviders;
use Illuminate\Support\ServiceProvider;

/**
 * Wires the SAML 2.0 Identity Provider module. Every capability is bound behind a
 * contract so a host can override the SP registry or key source, and so the
 * fakes in {@see Testing} can stand in during tests.
 */
class SamlIdpServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ServiceProviders::class, ServiceProviderRegistry::class);
        $this->app->singleton(IdpKeyMaterial::class, PlatformKeyMaterial::class);
        $this->app->singleton(SamlIdentityProvider::class, SamlIdentityProviderService::class);
        $this->app->singleton(SamlSingleLogout::class, SamlSingleLogoutService::class);

        // The interactive "authenticate the subject, then resume the SSO" step is
        // the HOST app's responsibility — this module serves parse/issue/metadata
        // and the auto-POST form, exactly as the OAuth server leaves /authorize to
        // the host. The thin controllers in the Api layer expose these.
    }
}
