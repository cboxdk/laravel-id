<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Contracts;

use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Cbox\Id\Webhooks\ValueObjects\RegisteredEndpoint;
use Illuminate\Support\Collection;

interface WebhookRegistry
{
    /**
     * @param  list<string>  $eventTypes
     */
    public function register(?string $organizationId, string $url, array $eventTypes): RegisteredEndpoint;

    /**
     * Pause an endpoint OWNED by this organization (null = the environment's own).
     * A mismatch is a silent no-op: the caller was not entitled to learn it exists.
     */
    public function pause(string $endpointId, ?string $organizationId): void;

    /**
     * Active endpoints (org-scoped or platform-wide) subscribed to the event type.
     *
     * @return Collection<int, WebhookEndpoint>
     */
    public function matching(?string $organizationId, string $eventType): Collection;
}
