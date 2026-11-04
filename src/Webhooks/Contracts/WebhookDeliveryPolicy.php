<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Contracts;

use Cbox\Id\Webhooks\Models\WebhookEndpoint;

/** A domain may narrow event delivery beyond the endpoint's subscription. */
interface WebhookDeliveryPolicy
{
    /** @param array<string, mixed> $payload */
    public function allows(WebhookEndpoint $endpoint, string $eventType, array $payload): bool;
}
