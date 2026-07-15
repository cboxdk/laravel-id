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

    public function pause(string $endpointId): void;

    public function activate(string $endpointId): void;

    public function remove(string $endpointId): void;

    /**
     * The ACTIVE endpoints for a hook point (what the pipeline will call), in
     * registration order.
     *
     * @return Collection<int, ExternalActionEndpoint>
     */
    public function active(HookPoint $hookPoint): Collection;
}
