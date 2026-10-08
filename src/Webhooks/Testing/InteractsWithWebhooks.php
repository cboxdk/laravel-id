<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Testing;

use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Contracts\WebhookSigningSchemes;
use Cbox\Id\Webhooks\Enums\SignatureScheme;
use Cbox\Id\Webhooks\ValueObjects\RegisteredEndpoint;

trait InteractsWithWebhooks
{
    /**
     * @param  list<string>  $eventTypes
     */
    protected function registerWebhook(?string $organizationId, string $url, array $eventTypes, SignatureScheme $scheme = SignatureScheme::Cbox): RegisteredEndpoint
    {
        // The default scheme keeps going through WebhookRegistry, so a test that swapped
        // the registry for a fake still registers through its fake.
        if ($scheme !== SignatureScheme::Cbox) {
            $schemes = app(WebhookSigningSchemes::class);

            return $organizationId === null
                ? $schemes->registerForEnvironmentWithScheme($url, $eventTypes, $scheme)
                : $schemes->registerWithScheme($organizationId, $url, $eventTypes, $scheme);
        }

        $registry = app(WebhookRegistry::class);

        // A test fixture keeps the nullable shorthand — writing a table of cases where one
        // row is platform-wide is exactly what it is for. Production callers do not: they
        // reach registerForEnvironment() by name.
        return $organizationId === null
            ? $registry->registerForEnvironment($url, $eventTypes)
            : $registry->register($organizationId, $url, $eventTypes);
    }
}
