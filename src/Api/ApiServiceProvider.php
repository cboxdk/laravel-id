<?php

declare(strict_types=1);

namespace Cbox\Id\Api;

use Cbox\Id\Api\Http\Controllers\AuthorizationServerMetadataController;
use Cbox\Id\Api\Http\Controllers\BackchannelAuthenticationController;
use Cbox\Id\Api\Http\Controllers\DecisionController;
use Cbox\Id\Api\Http\Controllers\DeviceAuthorizationController;
use Cbox\Id\Api\Http\Controllers\DiscoveryController;
use Cbox\Id\Api\Http\Controllers\EndSessionController;
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
use Cbox\Id\Api\Http\Controllers\Sso\SamlIdpLogoutController;
use Cbox\Id\Api\Http\Controllers\Sso\SamlIdpMetadataController;
use Cbox\Id\Api\Http\Controllers\Sso\SamlIdpSsoController;
use Cbox\Id\Api\Http\Controllers\Sso\SamlLoginController;
use Cbox\Id\Api\Http\Controllers\Sso\SamlLogoutController;
use Cbox\Id\Api\Http\Controllers\Sso\SamlMetadataController;
use Cbox\Id\Api\Http\Controllers\TokenController;
use Cbox\Id\Api\Http\Controllers\UserInfoController;
use Cbox\Id\Api\Http\Controllers\UserTokenIntrospectionController;
use Cbox\Id\Api\Http\Middleware\AuthenticateScim;
use Cbox\Id\Api\Http\Middleware\CanonicalIssuerHost;
use Cbox\Id\Api\Http\Middleware\NoStore;
use Cbox\Id\Api\Http\Middleware\ResolveEnvironment;
use Cbox\Id\Api\Http\Middleware\ScimContentType;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class ApiServiceProvider extends ServiceProvider
{
    /**
     * Laravel's CSRF middleware, under every name it has had.
     *
     * ALL THREE NAMES. Laravel 13's `web` group holds `PreventRequestForgery`;
     * `ValidateCsrfToken` and `VerifyCsrfToken` are deprecated SUBCLASSES of it, and
     * `Router::resolveMiddleware()` matches an exclusion in one direction only — the group
     * entry must be a subclass of the excluded name, not the other way round. Excluding
     * `VerifyCsrfToken` alone removes nothing at all, which is how a route stayed CSRF
     * protected for a year while the code said it was exempt. The reject loop skips a name
     * that does not exist, so listing the Laravel 12 classes beside the 13 one is safe
     * across the whole supported range.
     *
     * @var list<class-string>
     */
    private const CSRF_MIDDLEWARE = [
        PreventRequestForgery::class,
        ValidateCsrfToken::class,
        VerifyCsrfToken::class,
    ];

    public function boot(): void
    {
        // Liveness probe. Deliberately OUTSIDE both the environment resolution and the
        // IdP-surface gate below: a kubelet probes the POD (so the Host header maps to
        // no environment), and "this process is alive" must not depend on a database
        // lookup or on whether this particular host is allowed to be an issuer. A
        // liveness probe that can 404 restarts healthy pods.
        //
        // AND OUTSIDE THE RATE LIMITER, for the same reason one step further. This
        // carried `throttle:300,1`, and `ThrottleRequests` writes to the default cache
        // store — so the probe that answers "is this process alive" took a dependency on
        // the cache being reachable. A Redis or database blip then failed liveness on
        // every instance at once, the whole fleet restarted together, and each
        // replacement crash-looped against the same dependency it was waiting to
        // recover. The handler is a static `{"status":"ok"}`: there is no cost here to
        // limit, and no limiter that is worth taking a dependency for.
        Route::get('/up', HealthController::class);

        // Every request resolves its environment from the host first, pinning the
        // hard environment scope (own users, keys, issuer) for everything below.
        //
        // The host may then add its own gate (`cbox-id.api.middleware`, empty by
        // default) so a host that is NOT an identity provider — a multi-tenant
        // platform's account/signup root, say — 404s this whole surface instead of
        // advertising an issuer it cannot honour.
        // THE TOKEN ENDPOINTS, held to their own wall.
        //
        // Same throttle, same no-store, same environment resolution as the surface below
        // — what differs is only WHICH hosts serve them, and that is a question the host
        // application answers ({@see firstPartyMiddleware()}). It defaults to the surface
        // list, so a deployment that configures nothing sees no difference at all and the
        // single-tenant shape is untouched.
        //
        // Carved out because a deployment can have a host that must issue tokens to the
        // software it ships without being an identity provider for anybody else's app —
        // a management console whose own operators enrol authenticators, say. Folded into
        // the group below, those two facts could not be stated separately: one list
        // decided both, so making the console's own client work meant opening discovery,
        // dynamic registration and SCIM on the same host. Separating the endpoints is
        // what lets the host refuse the second while granting the first.
        Route::middleware(array_merge(
            [ResolveEnvironment::class],
            $this->firstPartyMiddleware(),
            ['throttle:30,1', NoStore::class],
        ))->group(function (): void {
            Route::post('/oauth/token', TokenController::class);
            Route::post('/oauth/revoke', RevocationController::class);
        });

        // THE PUBLIC VERIFICATION KEYS, on their own wall.
        //
        // Wherever this deployment issues a token it must publish the key to verify it.
        // The two are one fact and were gated by two different lists: a host could be
        // given the token endpoints above and not this, which is a signature nobody can
        // check — the same defect as advertising an endpoint that 404s, pointing the other
        // way. It happened: opening `/oauth/token` on a multi-tenant platform's own root
        // left JWKS behind, and an authenticator that verified against the host's key set
        // worked on a tenant subdomain and could never work on the root.
        //
        // Separate from `firstPartyMiddleware()` because this document names no client and
        // so cannot be gated on one — but it keeps `CanonicalIssuerHost`. An earlier pass
        // dropped it on the reasoning that a key set asserts nothing and so cannot
        // contradict itself. True, and beside the point: the reason metadata is held to the
        // canonical host is that an ALIAS which goes on answering protocol requests is a
        // surface the customer believes they have moved off. Keys are such a surface, and
        // `jwks_uri` names the canonical host anyway, so an alias serving them is only ever
        // reached by something that should not be pointed there. PerEnvironmentIssuerTest
        // holds it, and holds it for JWKS by name.
        Route::middleware(array_merge(
            [ResolveEnvironment::class, CanonicalIssuerHost::class],
            $this->verificationKeysMiddleware(),
            ['throttle:300,1'],
        ))->group(function (): void {
            Route::get('/.well-known/jwks.json', JwksController::class);
        });

        Route::middleware(array_merge([ResolveEnvironment::class], $this->surfaceMiddleware()))->group(function (): void {
            // Public metadata — cheap, cacheable, generously throttled, and the ONLY
            // group held to the environment's canonical host. These are the documents
            // that ASSERT an issuer, so an alias serving them contradicts itself and
            // conformant clients refuse the result. Everything below either
            // authenticates by credential — where a cross-origin redirect strips the
            // credential rather than moving the call — or names no host at all, and
            // wrapping the whole surface in this broke both ({@see CanonicalIssuerHost}).
            Route::middleware(['throttle:300,1', CanonicalIssuerHost::class])->group(function (): void {
                Route::get('/.well-known/openid-configuration', DiscoveryController::class);
                // RFC 8414 + RFC 9728 — the metadata MCP clients discover the server by.
                Route::get('/.well-known/oauth-authorization-server', AuthorizationServerMetadataController::class);
                Route::get('/.well-known/oauth-protected-resource', ProtectedResourceMetadataController::class);

                // IdP-role SAML metadata (this platform AS the IdP) — public,
                // imported by a relying SP during federation setup. Registered before
                // the `{connection}` route below so the literal `idp` segment wins.
                Route::get('/sso/saml/idp/metadata', SamlIdpMetadataController::class);
            });

            // UserInfo (OIDC §5.3) — bearer-authenticated, called per session.
            Route::middleware('throttle:120,1')->match(['get', 'post'], '/oauth/userinfo', UserInfoController::class);

            // Authorization decision endpoint (hot path): permission + entitlement
            // checks resolved live. Generously throttled — resource servers call it per
            // request and it is cache-backed.
            Route::middleware('throttle:600,1')->post('/oauth/decisions', DecisionController::class);

            // Credential-bearing endpoints — throttled to blunt secret/token brute
            // force (secrets are 256-bit, so this is a backstop, not the only guard),
            // and no-store so a proxy/CDN/back-button can never re-serve a token
            // (RFC 6749 §5.1, RFC 7662 §2.2). On the GROUP so a newly added endpoint
            // inherits it rather than being one forgotten line from caching credentials.
            Route::middleware(['throttle:30,1', NoStore::class])->group(function (): void {
                Route::post('/oauth/introspect', IntrospectionController::class);

                // User API tokens (cbid_pat_): introspection for relying-party
                // services. Same posture as OAuth introspection.
                Route::post('/user-tokens/introspect', UserTokenIntrospectionController::class);

                // RFC 9126: back-channel pushed authorization requests.
                Route::post('/oauth/par', PushedAuthorizationController::class);

                // RFC 8628: device authorization grant (TVs, CLIs, IoT).
                Route::post('/oauth/device_authorization', DeviceAuthorizationController::class);

                // OIDC CIBA: client-initiated backchannel authentication (agents).
                Route::post('/oauth/backchannel_authentication', BackchannelAuthenticationController::class);
            });

            Route::middleware(['web', 'throttle:30,1'])->group(function (): void {
                // OIDC RP-Initiated Logout (end_session_endpoint) — browser redirect,
                // so it needs the web session it is about to tear down. Both bindings
                // (GET query params, POST form) are accepted.
                // POST is mandatory here (RP-Initiated Logout §5) and arrives cross-site
                // from the relying party, so the same reasoning applies. Nothing is
                // minted; the open-redirect guard is the registered
                // post_logout_redirect_uri allow-list, compared exactly.
                Route::match(['get', 'post'], '/oauth/logout', EndSessionController::class)
                    ->withoutMiddleware(self::CSRF_MIDDLEWARE);

                // IdP-role endpoints (this platform AS the IdP a downstream SP
                // federates to). Registered before the `{connection}` routes below so
                // the literal `idp` segment wins the match. The SSO endpoint needs a
                // session so it can hand off to the host's login and resume; both
                // bindings (redirect GET, POST) are accepted. Validation is
                // deny-by-default in the IdP contract.
                //
                // CSRF EXEMPT ON THE POST BINDING, which is the one this platform's own
                // published metadata advertises: an SP or IdP posting a signed SAML
                // message cross-site cannot carry a Laravel session token, and there is
                // no version of SAML in which it could. Every such POST met a 419 in
                // HTML — a logout the SP reported as a transport failure while the
                // session here stayed live. The signature over the message is the
                // authentication, verified before any identity is read.
                //
                // The host application should not have to know this. The reference
                // console carried these exemptions in its own bootstrap for months while
                // the package shipped routes that answered 419 to anyone else who
                // installed it, which is the whole class of defect where the only
                // deployment that works is the one we run.
                Route::match(['get', 'post'], '/sso/saml/idp/sso', SamlIdpSsoController::class)
                    ->withoutMiddleware(self::CSRF_MIDDLEWARE);
                Route::match(['get', 'post'], '/sso/saml/idp/slo', SamlIdpLogoutController::class)
                    ->withoutMiddleware(self::CSRF_MIDDLEWARE);

                // Dynamic Client Registration (RFC 7591) + management (RFC 7592). The
                // controller enforces the configured mode (disabled/protected/open).
                //
                // no-store: registration returns client_secret and
                // registration_access_token, which RFC 7591 §5 makes a MUST. These sit
                // outside the credential group above, which is exactly the "one
                // forgotten line" the middleware exists to prevent.
                //
                // Also CSRF exempt: this is a back-channel JSON API and no conformant
                // client sends a Laravel token. The credential is the registration access
                // token (RFC 7592 §2), presented as a bearer.
                Route::middleware(NoStore::class)->withoutMiddleware(self::CSRF_MIDDLEWARE)->group(function (): void {
                    Route::post('/oauth/register', RegistrationController::class);
                    Route::get('/oauth/register/{client}', [RegisteredClientController::class, 'show']);
                    Route::put('/oauth/register/{client}', [RegisteredClientController::class, 'update']);
                    Route::delete('/oauth/register/{client}', [RegisteredClientController::class, 'destroy']);
                });
            });

            // SCIM 2.0 provisioning, authenticated by the directory bearer token.
            // ScimContentType runs OUTSIDE the throttle so a 429 is framed as a SCIM
            // Error too: a rate-limited Okta full import used to receive Laravel's
            // `{"message":"Too Many Attempts."}` in application/json and treat the
            // unparsable body as a fatal connector error rather than backing off.
            Route::middleware([ScimContentType::class, 'throttle:120,1', AuthenticateScim::class])->prefix('scim/v2')->group(function (): void {
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
        });

        /*
         * INBOUND federation — deliberately OUTSIDE the IdP-surface gate above.
         *
         * The gate answers "may this host act as an ISSUER?": discovery, JWKS, the
         * OAuth/OIDC endpoints, SCIM, and the IdP-role SAML endpoints. These routes are
         * the opposite role — this server as the RELYING party, consuming an assertion
         * from someone else's IdP — and a host that is not an issuer can still legitimately
         * federate. A multi-tenant platform's account/root host is exactly that case: the
         * account's own organization has an SSO connection, home-realm discovery sends the
         * member to `/sso/oidc/{connection}/redirect` on the host they are already on, and
         * the assertion has to come back to that same host. Gating these as issuer surface
         * 404'd the redirect, the callback and the SP metadata there, so an account whose
         * org requires SSO could not reach its own workspace at all.
         *
         * The real boundary is the `Connection`'s environment scope, not the host: an
         * unknown or out-of-environment connection id resolves to nothing here, on every
         * host. Registered AFTER the group above so the literal `/sso/saml/idp/*` segments
         * still win over `{connection}`.
         */
        Route::middleware([ResolveEnvironment::class])->group(function (): void {
            // SP SAML metadata for a connection — public, no secrets, imported by the
            // IdP admin during connector setup. Unreachable metadata means the connection
            // cannot be set up in the first place.
            Route::middleware('throttle:300,1')->get('/sso/saml/{connection}/metadata', SamlMetadataController::class);

            // SAML ACS — unauthenticated; the assertion's XML signature is the auth.
            Route::middleware(['throttle:30,1', NoStore::class])
                ->post('/sso/saml/{connection}/acs', SamlAcsController::class);

            // Browser redirect flows, so they need a session for state/nonce and for the
            // SAML InResponseTo request id.
            Route::middleware(['web', 'throttle:30,1'])->group(function (): void {
                // OIDC (RP-initiated) login. The id_token signature + nonce are the auth.
                Route::get('/sso/oidc/{connection}/redirect', OidcRedirectController::class);

                // AND POST, because `response_mode=form_post` is a thing providers choose
                // for us. Apple switches to it the moment a scope beyond `openid` is asked
                // for; a GET-only redirect URI answers that with 405, and the person sees
                // a blank failure that looks exactly like they cancelled. The callback
                // reads `state`/`code` from the query or the body indifferently, and
                // `state` — not the framework's CSRF token, which a cross-site POST from a
                // provider cannot carry — is what proves the answer belongs to this
                // browser. See {@see \Cbox\Id\Federation\Support\FederationFlowStash}.
                //
                // ALL THREE NAMES. Laravel 13's `web` group holds
                // `PreventRequestForgery`; `ValidateCsrfToken` and `VerifyCsrfToken` are
                // deprecated SUBCLASSES of it, and `Router::resolveMiddleware()` matches
                // an exclusion in one direction only — the group entry must be a subclass
                // of the excluded name, not the other way round. Excluding
                // `VerifyCsrfToken` alone therefore removed nothing at all, and the route
                // answered 419 to the very POST it was opened for. The reject loop skips
                // a name that does not exist, so listing the Laravel 12 classes beside
                // the 13 one is safe across the whole supported range.
                Route::match(['get', 'post'], '/sso/oidc/{connection}/callback', OidcCallbackController::class)
                    ->withoutMiddleware([
                        PreventRequestForgery::class,
                        ValidateCsrfToken::class,
                        VerifyCsrfToken::class,
                    ]);

                // SP-initiated SAML login (AuthnRequest). Single Logout accepts the IdP's
                // redirect (GET) and, for some IdPs, POST — it belongs with the login it
                // undoes, or a federated member could sign in but never sign out.
                Route::get('/sso/saml/{connection}/login', SamlLoginController::class);
                // Single Logout in the SP role: the customer's IdP posts a signed
                // LogoutRequest here, cross-site and tokenless, exactly as it does to the
                // IdP-role endpoint above. Same exemption, same reason.
                Route::match(['get', 'post'], '/sso/saml/{connection}/slo', SamlLogoutController::class)
                    ->withoutMiddleware(self::CSRF_MIDDLEWARE);
            });
        });
    }

    /**
     * Host-declared middleware wrapped around the whole IdP protocol surface.
     *
     * This package is a LIBRARY: it cannot know whether a given host of the host
     * application is supposed to be an identity provider, and it must not depend on the
     * host's own answer. So it takes a list and applies it, with a permissive default —
     * configure nothing and every host serves everything, which is exactly right for the
     * single-tenant / self-hosted shape.
     *
     * Anything that is not a non-empty string is dropped rather than handed to the
     * router: a malformed entry would otherwise surface as an unrelated routing
     * exception on the first request to any protocol endpoint.
     *
     * @return list<string>
     */
    private function surfaceMiddleware(): array
    {
        $configured = config('cbox-id.api.middleware', []);

        if (! is_array($configured)) {
            return [];
        }

        return $this->stringList($configured);
    }

    /**
     * Host-declared middleware for the public key set alone.
     *
     * Defaults to {@see firstPartyMiddleware()} — which itself defaults to the surface
     * list — so a deployment that configures nothing keeps JWKS exactly where the rest of
     * the protocol surface is, and one that opens the token endpoints somewhere gets the
     * keys to match unless it says otherwise.
     *
     * @return list<string>
     */
    private function verificationKeysMiddleware(): array
    {
        $configured = config('cbox-id.api.verification_keys_middleware');

        if (! is_array($configured)) {
            return $this->firstPartyMiddleware();
        }

        return $this->stringList($configured);
    }

    /**
     * Host-declared middleware for the TOKEN endpoints alone — `/oauth/token` and
     * `/oauth/revoke`.
     *
     * Defaults to {@see surfaceMiddleware()}, so this is inert until a deployment states
     * otherwise: configuring nothing, or configuring only `api.middleware`, keeps the
     * token endpoints exactly where the rest of the protocol surface is.
     *
     * @return list<string>
     */
    private function firstPartyMiddleware(): array
    {
        $configured = config('cbox-id.api.first_party_middleware');

        if (! is_array($configured)) {
            return $this->surfaceMiddleware();
        }

        return $this->stringList($configured);
    }

    /**
     * The non-empty strings in a configured list, in order.
     *
     * Anything else is dropped rather than handed to the router: a malformed entry would
     * otherwise surface as an unrelated routing exception on the first request to any
     * protocol endpoint, which is a long way from the config line that caused it.
     *
     * @param  array<array-key, mixed>  $configured
     * @return list<string>
     */
    private function stringList(array $configured): array
    {
        $middleware = [];

        foreach ($configured as $entry) {
            if (is_string($entry) && $entry !== '') {
                $middleware[] = $entry;
            }
        }

        return $middleware;
    }
}
