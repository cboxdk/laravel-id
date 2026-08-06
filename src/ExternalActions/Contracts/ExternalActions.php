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
     * Register an endpoint for a hook point. Returns the endpoint plus its plaintext
     * signing secret, shown exactly once.
     *
     * @throws UnsafeActionUrl when the URL fails the SSRF guard
     */
    public function register(HookPoint $hookPoint, string $url, ?string $organizationId = null): RegisteredActionEndpoint;

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
