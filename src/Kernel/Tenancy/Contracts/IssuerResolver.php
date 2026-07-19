<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Contracts;

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
}
