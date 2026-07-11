<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events;

use Cbox\Id\Kernel\Events\Models\Event;

/**
 * Dispatched on Laravel's event dispatcher when an outbox row is delivered.
 * Downstream modules (webhooks, projections) listen for this. Delivery is
 * at-least-once, so listeners must be idempotent (use {@see Event::$id}).
 */
final class EventDelivered
{
    public function __construct(public readonly Event $event) {}
}
