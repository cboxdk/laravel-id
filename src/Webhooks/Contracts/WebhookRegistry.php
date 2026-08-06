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

    /**
     * Every ACTIVE endpoint an organization's events can reach — its own plus the
     * environment's platform-wide ones — whatever they subscribe to.
     *
     * The LISTING counterpart to {@see matching()}, which answers a delivery question and
     * so must take an event type. A caller that wanted "which endpoints does this
     * organization have" had only matching() to ask with, and recovered the answer by
     * unioning a list of candidate event types: one full read per candidate, against a
     * subscription filter that has always run in PHP anyway. That idiom got one query
     * worse every time the platform learned to emit something new.
     *
     * @return Collection<int, WebhookEndpoint>
     */
    public function forOrganization(?string $organizationId): Collection;
}
