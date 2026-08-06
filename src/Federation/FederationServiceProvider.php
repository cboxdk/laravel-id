<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\DnsResolver;
use Cbox\Id\Federation\Contracts\DomainVerification;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Cbox\Id\Federation\Contracts\OidcRelyingParty;
use Cbox\Id\Federation\Contracts\SamlSpSingleLogout;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Saml\SamlLogout;
use Cbox\Id\Federation\Saml\SamlMetadataImporter;
use Cbox\Id\Federation\Validators\DispatchingAssertionValidator;
use Cbox\Id\Federation\Validators\OidcAssertionValidator;
use Cbox\Id\Federation\Validators\SamlAssertionValidator;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class FederationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Connections::class, ConnectionService::class);
        $this->app->singleton(FederationFlow::class, FederationLoginService::class);
        $this->app->singleton(DnsResolver::class, SystemDnsResolver::class);
        $this->app->singleton(DomainVerification::class, DatabaseDomainVerification::class);

        // The two protocol halves the HTTP layer drives directly. Bound to contracts
        // like every other collaborator above, so the SSO controllers depend on the
        // module's published surface rather than reaching past it into a concrete class.
        $this->app->singleton(OidcRelyingParty::class, OidcClient::class);
        $this->app->singleton(SamlSpSingleLogout::class, SamlLogout::class);

        // Enterprise SSO onboarding: parse an IdP's SAML metadata (paste or URL)
        // into a connection prefill via the vetted onelogin parser.
        $this->app->singleton(SamlMetadataImporter::class);
        $this->app->singleton(OidcDiscovery::class);

        // Per-type signature validation, each wrapping a vetted library: OIDC
        // (id_token / JWS via firebase/php-jwt, RS256-pinned) and SAML (XML-DSig
        // via onelogin/php-saml, with XSW/XXE defense). A type with no validator
        // is rejected, never silently trusted.
        $this->app->singleton(AssertionValidator::class, function (Application $app): DispatchingAssertionValidator {
            return new DispatchingAssertionValidator([
                ConnectionType::Oidc->value => $app->make(OidcAssertionValidator::class),
                ConnectionType::Saml->value => $app->make(SamlAssertionValidator::class),
            ]);
        });
    }
}
