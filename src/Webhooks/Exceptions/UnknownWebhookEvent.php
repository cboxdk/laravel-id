<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Exceptions;

use Cbox\Id\Webhooks\Enums\WebhookEventType;
use InvalidArgumentException;

/**
 * Thrown when an endpoint tries to subscribe to an event type that is not in the
 * {@see WebhookEventType} catalog (nor the `*` wildcard).
 * Subscriptions are deny-by-default so a typo is caught at registration, not left
 * to surface as silently-missing deliveries.
 */
class UnknownWebhookEvent extends InvalidArgumentException
{
    public static function forType(string $eventType): self
    {
        return new self('unknown webhook event type: '.$eventType);
    }
}
