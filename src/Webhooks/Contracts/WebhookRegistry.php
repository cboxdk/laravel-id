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

    public function pause(string $endpointId): void;

    /**
     * Active endpoints (org-scoped or platform-wide) subscribed to the event type.
     *
     * @return Collection<int, WebhookEndpoint>
     */
    public function matching(?string $organizationId, string $eventType): Collection;
}
