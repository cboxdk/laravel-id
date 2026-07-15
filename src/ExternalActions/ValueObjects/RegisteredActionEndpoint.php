<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\ValueObjects;

use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;

/**
 * Returned once at registration: the endpoint plus its plaintext signing secret,
 * which is never retrievable again (only the sealed form is stored). The receiver
 * uses this secret to verify the `X-Cbox-Signature` on each hook request.
 */
final readonly class RegisteredActionEndpoint
{
    public function __construct(
        public ExternalActionEndpoint $endpoint,
        public string $secret,
    ) {}
}
