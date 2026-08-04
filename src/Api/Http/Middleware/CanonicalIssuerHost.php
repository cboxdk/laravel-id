<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Middleware;

use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Organization\DatabaseEnvironmentResolver;
use Closure;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * ONE issuer, ONE host. Redirects the IdP protocol surface from any alias of an
 * environment to the host its issuer actually names.
 *
 * OIDC Discovery §4.3 and RFC 8414 §3.3 both make `issuer` == the URL the document was
 * fetched from a MUST, and every conformant client checks it: node-openid-client,
 * oauth4webapi, Spring Security, MSAL and pyoidc all refuse a document that fails it.
 * An environment can be reachable on more than one name, though — a tenant onboarded at
 * `acme.cboxid.com` still resolves there after it verifies `id.acme.com`
 * ({@see DatabaseEnvironmentResolver} matches either) — so without
 * this the alias served a full protocol surface advertising the other host's identity,
 * and every relying party configured against the alias broke at once, from a domain
 * verification nobody would connect to them.
 *
 * The alternative was to let the issuer follow whichever host the request arrived on.
 * That was rejected: `forEnvironment()` mints tokens with no request in scope at all
 * (queue workers, the outbox relay, CIBA), so there is no host to follow there, and the
 * two hosts would in any case be two live issuers sharing one keystore — an environment
 * whose subjects have two `(iss, sub)` identities at the same relying party.
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
        $canonical = $this->issuers->canonicalHost();

        // Host only — never scheme or port. A deployment terminating TLS at a proxy sees
        // http:// on the wire while its issuer says https://, and comparing more than the
        // host would put every one of those requests into a redirect that resolves to
        // itself.
        if ($canonical === null || strcasecmp($request->getHost(), $canonical) === 0) {
            return $next($request);
        }

        $target = $this->issuers->issuer().$request->getRequestUri();

        // 301 for the safe methods, so a client and its caches learn the move once. 308
        // for the rest: the credential-bearing endpoints are POSTs, and 301/302 let a
        // client rewrite the method to GET — which would drop the body and answer a
        // token request with a 405 rather than a token.
        return new RedirectResponse($target, $request->isMethodSafe() ? 301 : 308);
    }
}
