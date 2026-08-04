<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Contracts;

use Cbox\Id\Api\Http\Middleware\CanonicalIssuerHost;

/**
 * Resolves the canonical issuer identifier (an `https://` origin, no trailing slash)
 * for the environment a request/token belongs to. This is the single source of truth
 * behind the OIDC/OAuth `iss`, the discovery `issuer` + endpoint URLs, and the SAML
 * IdP entityID — so a token minted on a tenant's subdomain advertises THAT host,
 * matching the per-environment signing key it is signed with (RFC 8414 §3.3: the
 * published issuer must equal the host the metadata is served from).
 *
 * The platform-root (is_default) environment and the single-tenant / on-prem shape
 * keep the configured `cbox-id.issuer` (the apex), so their existing identity is
 * unchanged; only tenant environments on their own subdomain/custom-domain resolve
 * to their own issuer.
 */
interface IssuerResolver
{
    /** The issuer for the currently-active environment (context-resolved), or the fallback. */
    public function issuer(): string;

    /** The issuer for a specific environment key — for minting outside the active context. */
    public function forEnvironment(string $environmentKey): string;

    /**
     * The ONE host the active environment's issuer is bound to, or null when it has no
     * issuer identity of its own and inherits the deployment-wide configured one.
     *
     * The distinction is what makes the §3.3 invariant above enforceable rather than
     * merely asserted. An environment that owns a host (a verified custom domain, or its
     * `{slug}.{base_domain}`) stays REACHABLE on the other one too — a tenant onboarded
     * at `acme.cboxid.com` keeps resolving there after it verifies `id.acme.com` — and
     * that alias would otherwise serve a metadata document naming a host it was not
     * fetched from, which conformant clients reject. Naming the canonical host is what
     * lets the surface redirect the alias instead
     * ({@see CanonicalIssuerHost}).
     *
     * Null is the ordinary answer for the platform-root environment and for every
     * single-tenant / on-prem deployment: their issuer is operator-configured and
     * host-independent by design, so an internal load-balancer name, a health probe or a
     * second ingress may all legitimately serve it.
     */
    public function canonicalHost(): ?string;
}
