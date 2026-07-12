<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Testing;

use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\ValueObjects\RegisteredEndpoint;

trait InteractsWithWebhooks
{
    /**
     * @param  list<string>  $eventTypes
     */
    protected function registerWebhook(?string $organizationId, string $url, array $eventTypes): RegisteredEndpoint
    {
        return app(WebhookRegistry::class)->register($organizationId, $url, $eventTypes);
    }
}
