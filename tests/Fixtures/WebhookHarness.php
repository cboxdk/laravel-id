<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Webhooks\Testing\InteractsWithWebhooks;

/**
 * Composition site so the shippable InteractsWithWebhooks trait is type-checked.
 */
final class WebhookHarness
{
    use InteractsWithWebhooks;
}
