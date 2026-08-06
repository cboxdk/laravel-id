<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Models\Client;

/**
 * Returned once at registration: the client plus its plaintext secret (null for
 * public clients), which is never retrievable again — only the hash is stored.
 */
readonly class RegisteredClient
{
    public function __construct(
        public Client $client,
        public ?string $secret,
    ) {}
}
