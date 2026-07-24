<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\ValueObjects;

use Cbox\Id\Webhooks\Models\WebhookEndpoint;

/**
 * Returned once at registration: the endpoint plus its plaintext signing secret,
 * which is never retrievable again (only the sealed form is stored).
 */
readonly class RegisteredEndpoint
{
    public function __construct(
        public WebhookEndpoint $endpoint,
        public string $secret,
    ) {}
}
