<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

use Cbox\Id\Federation\Exceptions\DomainAlreadyClaimed;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Models\VerifiedDomain;

/**
 * DNS-based domain verification and home-realm discovery. An organization proves
 * control of an email domain by publishing a TXT challenge; once verified, users
 * at that domain can be routed to the org's SSO. Resolution is deny-by-default —
 * an unverified domain never routes and never captures.
 */
interface DomainVerification
{
    /**
     * Register a domain for an organization (unverified) and mint its DNS
     * challenge token. Idempotent for the same org+domain.
     *
     * Another organization's PENDING claim does not refuse: each organization gets its
     * own challenge, and the first to prove the domain owns it.
     *
     * @throws DomainAlreadyClaimed when another org
     *                              has already verified the domain in this environment
     */
    public function add(string $organizationId, string $domain): VerifiedDomain;

    /**
     * Re-check the DNS challenge and mark the domain verified if the token is
     * present and no other organization has verified it first. Idempotent;
     * returns whether the domain is now verified.
     */
    public function verify(string $id): bool;

    /**
     * Toggle the optional capture gate on a (verified) domain.
     */
    public function setCapture(string $id, bool $capture): void;

    public function remove(string $id): void;

    /**
     * @return list<VerifiedDomain>
     */
    public function forOrganization(string $organizationId): array;

    /**
     * The VERIFIED domain matching an email address, or null. Unverified domains
     * are never returned (deny-by-default).
     */
    public function forEmail(string $email): ?VerifiedDomain;

    /**
     * The active SSO connection a given email should be routed to via its verified
     * domain — the home-realm-discovery entry point. Null when the domain is
     * unverified or the org has no active connection.
     */
    public function connectionForEmail(string $email): ?Connection;

    /**
     * The DNS host where the org must publish the TXT challenge for a domain
     * (e.g. `_cbox-id-challenge.acme.com`).
     */
    public function challengeHost(string $domain): string;
}
