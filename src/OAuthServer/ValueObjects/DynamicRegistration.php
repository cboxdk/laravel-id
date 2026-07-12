<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Models\Client;

/**
 * The result of a successful RFC 7591 registration: the created client, its
 * plaintext secret (null for public clients), and the RFC 7592 registration
 * access token. Both secrets are returned exactly once — only their hashes are
 * persisted.
 */
final readonly class DynamicRegistration
{
    public function __construct(
        public Client $client,
        public ?string $secret,
        public string $registrationAccessToken,
    ) {}
}
