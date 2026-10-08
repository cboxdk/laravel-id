<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\ValueObjects;

use Cbox\Id\Webhooks\Enums\SignatureScheme;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;

/**
 * Returned once at registration: the endpoint plus its plaintext signing secret,
 * which is never retrievable again (only the sealed form is stored).
 *
 * The secret's form follows the scheme: 64 hex characters for {@see SignatureScheme::Cbox},
 * `whsec_` + base64 for {@see SignatureScheme::StandardWebhooks}.
 */
readonly class RegisteredEndpoint
{
    public function __construct(
        public WebhookEndpoint $endpoint,
        public string $secret,
    ) {}

    /** How the endpoint's deliveries are signed — read from the endpoint, never stored twice. */
    public function signatureScheme(): SignatureScheme
    {
        return $this->endpoint->signature_scheme;
    }
}
