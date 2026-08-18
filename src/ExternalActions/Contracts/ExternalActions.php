<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Contracts;

use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Exceptions\UnsafeActionUrl;
use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\ExternalActions\ValueObjects\RegisteredActionEndpoint;
use Illuminate\Support\Collection;

/**
 * Manages the external HTTP hook endpoints — the customer URLs the platform calls
 * at a {@see HookPoint}. Registration SSRF-guards the URL and mints a reveal-once
 * signing secret (sealed at rest). Everything is environment-owned.
 */
interface ExternalActions
{
    /**
     * Register an endpoint OWNED by one organization: it is consulted for that
     * organization's hook point and no other's. Returns the endpoint plus its plaintext
     * signing secret, shown exactly once.
     *
     * @throws UnsafeActionUrl when the URL fails the SSRF guard
     */
    public function register(HookPoint $hookPoint, string $url, string $organizationId): RegisteredActionEndpoint;

    /**
     * Register an endpoint consulted for EVERY organization in this environment.
     *
     * Its own method, and the organization id is no longer an optional trailing argument
     * defaulting to null. At most of these hook points an endpoint can REFUSE the
     * operation — `token_minting` decides whether a token is issued at all — so one
     * caller who forgot the third argument registered a URL able to stop every tenant in
     * the environment signing in. A default that hands out the widest possible scope is
     * the wrong default; now the widest scope has to be asked for by name.
     *
     * Only an operator/environment-plane caller may use this.
     *
     * @throws UnsafeActionUrl when the URL fails the SSRF guard
     */
    public function registerForEnvironment(HookPoint $hookPoint, string $url): RegisteredActionEndpoint;

    /*
     * Management takes the ACTING organization and matches it exactly: a tenant admin
     * manages only their own hooks, and the environment's own (organization_id null)
     * hooks belong to the operator. Pass null to act as the environment. A mismatch is
     * a silent no-op rather than an error — the caller was not entitled to learn the
     * endpoint exists.
     */
    public function pause(string $endpointId, ?string $organizationId): void;

    public function activate(string $endpointId, ?string $organizationId): void;

    public function remove(string $endpointId, ?string $organizationId): void;

    /**
     * The ACTIVE endpoints for a hook point (what the pipeline will call), in
     * registration order, for the organization the pipeline is running FOR: that org's
     * own hooks plus the environment-wide ones. Never another tenant's.
     *
     * @return Collection<int, ExternalActionEndpoint>
     */
    public function active(HookPoint $hookPoint, ?string $organizationId): Collection;
}
