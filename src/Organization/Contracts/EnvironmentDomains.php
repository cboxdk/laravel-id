<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\Organization\Exceptions\InvalidCustomDomain;
use Cbox\Id\Organization\ValueObjects\DomainChallenge;

/**
 * Self-serve custom-domain verification for an environment. An admin requests a
 * domain; the IdP hands back a DNS TXT challenge; once the record is live, {@see
 * verify()} promotes the domain to the environment's issuer host (read by the
 * per-environment issuer resolver).
 *
 * The IdP is deliberately TLS-AGNOSTIC: it proves domain control and records the
 * host, but issuing the certificate is the deployment's ingress concern (cert-manager,
 * on-demand TLS, …), documented for operators — the app never couples itself to
 * cluster RBAC. Deny-by-default: a malformed, platform-reserved, or already-claimed
 * domain is refused, and a domain is never promoted until its TXT record verifies.
 */
interface EnvironmentDomains
{
    /**
     * The pending challenge for an environment, or null when none is in progress
     * (the environment either has no custom domain or a verified one).
     */
    public function challenge(string $environmentKey): ?DomainChallenge;

    /**
     * Begin (or replace) verification for a domain, returning the DNS TXT record to
     * publish. Does not touch the live issuer host until {@see verify()} succeeds.
     *
     * @throws InvalidCustomDomain
     */
    public function request(string $environmentKey, string $domain): DomainChallenge;

    /**
     * Check the challenge's TXT record. On a match, promote the domain to the
     * environment's issuer host and clear the pending challenge; the returned
     * challenge reports whether it verified.
     */
    public function verify(string $environmentKey): DomainChallenge;

    /**
     * Remove the custom domain (pending or verified); the environment falls back to
     * its `{slug}.{base_domain}` / configured issuer.
     */
    public function clear(string $environmentKey): void;
}
