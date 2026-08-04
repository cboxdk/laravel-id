<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Middleware;

use Cbox\Id\Api\ApiServiceProvider;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Organization\Contracts\EnvironmentDomains;
use Cbox\Id\Organization\DatabaseEnvironmentResolver;
use Cbox\Id\Organization\EnvironmentDomainService;
use Closure;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * ONE issuer, ONE host — for the documents that ASSERT a host.
 *
 * OIDC Discovery §4.3 and RFC 8414 §3.3 both make `issuer` == the URL the document was
 * fetched from a MUST, and every conformant client checks it: node-openid-client,
 * oauth4webapi, Spring Security, MSAL and pyoidc all refuse a document that fails it.
 * An environment can be reachable on more than one name, though — a tenant onboarded at
 * `acme.cboxid.com` still resolves there after it verifies `id.acme.com`
 * ({@see DatabaseEnvironmentResolver} matches either) — so without this the alias served
 * metadata advertising the other host's identity, and every relying party configured
 * against the alias broke at once, from a domain verification nobody would connect
 * to them.
 *
 * The alternative was to let the issuer follow whichever host the request arrived on.
 * That was rejected: `forEnvironment()` mints tokens with no request in scope at all
 * (queue workers, the outbox relay, CIBA), so there is no host to follow there, and the
 * two hosts would in any case be two live issuers sharing one keystore — an environment
 * whose subjects have two `(iss, sub)` identities at the same relying party.
 *
 * WHAT THIS IS MOUNTED ON, AND WHY IT IS ONLY THAT. Metadata, and nothing else
 * ({@see ApiServiceProvider}). This used to wrap the whole IdP surface, which was a
 * category error with three teeth:
 *
 *  - The back channel authenticates by CREDENTIAL, not by issuer identity, and HTTP
 *    clients drop `Authorization` across origins. Redirecting `/oauth/token`,
 *    `/introspect`, `/revoke`, `/userinfo` or SCIM therefore did not move the call — it
 *    turned it into a 401. SCIM has no issuer concept at all: the §3.3 argument that
 *    justifies redirecting metadata does not reach it even in principle, and Okta and
 *    Entra provisioning against the alias worked until this arrived.
 *  - A cross-site form POST cannot be redirected at all. `form-action` is enforced across
 *    the WHOLE redirect chain, so an SP whose CSP names only the alias has the browser
 *    block a 308 on `POST /sso/saml/idp/sso` — the federation fails in the browser,
 *    where no server log will show it.
 *  - Verification proves TXT control, not reachability. {@see EnvironmentDomains} is
 *    explicit that TLS and routing are the ingress's job, so between the DNS challenge
 *    completing and the ingress catching up, the canonical host may have no certificate
 *    and no route. Redirecting metadata alone makes that window cost discovery; wrapping
 *    the surface made it cost every protocol call the tenant had.
 *
 * The browser authorization surface is deliberately NOT redirected either. Nothing it
 * serves names a host: the `iss` of the authorization response (RFC 9207), of the
 * id_token, and the SAML Response's `Issuer` are all the canonical issuer whichever host
 * answered, so an alias serves a correct flow rather than a contradicting one. A client
 * driven by discovery already arrives at the canonical `authorization_endpoint` because
 * the document it just fetched names it — and one hardcoded to the alias keeps working
 * instead of being broken by a redirect its CSP forbids.
 *
 * Only aliases of an environment that OWNS a host are redirected. The platform root and
 * every single-tenant / on-prem deployment inherit a configured, host-independent issuer
 * and are left alone, so an internal load-balancer name or a second ingress keeps serving
 * ({@see IssuerResolver::canonicalHost()}).
 */
final class CanonicalIssuerHost
{
    public function __construct(private readonly IssuerResolver $issuers) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Safe methods only, as a property of the middleware rather than of where it
        // happens to be mounted. Metadata is GET-only today, so this branch is unreachable
        // from the current route table — it is here so that mounting this on a surface
        // that also answers POST degrades to "serve it" rather than to a redirect the
        // browser blocks or the HTTP client strips the credential from.
        if (! $request->isMethodSafe()) {
            return $next($request);
        }

        $canonical = $this->issuers->canonicalHost();

        // Host only — never scheme or port. A deployment terminating TLS at a proxy sees
        // http:// on the wire while its issuer says https://, and comparing more than the
        // host would put every one of those requests into a redirect that resolves to
        // itself.
        if ($canonical === null || strcasecmp($request->getHost(), $canonical) === 0) {
            return $next($request);
        }

        // 302 + no-store, NOT 301. A custom domain is not permanent: clearing it
        // ({@see EnvironmentDomainService::clear()}) reverts `domain` to null and the
        // alias becomes canonical again. RFC 9111 §4.2.2 makes a 301 heuristically
        // cacheable with no freshness information at all, which browsers read as
        // "forever" — so the permanent spelling would strand every client that saw it on
        // a host that no longer resolves, with nothing the operator could do to unwind it.
        return new RedirectResponse(
            $this->issuers->issuer().$request->getRequestUri(),
            302,
            ['Cache-Control' => 'no-store'],
        );
    }
}
