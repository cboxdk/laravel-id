<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Models\Client;

/**
 * The result of an RFC 7592 management update.
 *
 * Carries a secret ONLY when the update moved the client into a shared-secret method it
 * had none for — a client that had rotated to `private_key_jwt` and back would otherwise
 * arrive at `client_secret_basic` with no password, unable to authenticate, and nothing in
 * the response saying so.
 *
 * A value object rather than a tuple for the reason the rest of this package uses them:
 * `[$client, $secret]` reads identically to `[$secret, $client]` at the call site, and the
 * one thing in it that must not be mishandled is the secret.
 */
readonly class UpdatedRegistration
{
    public function __construct(
        public Client $client,
        /** The new secret, plaintext and readable exactly once, or null when unchanged. */
        public ?string $secret = null,
    ) {}
}
