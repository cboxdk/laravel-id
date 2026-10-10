<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\ValueObjects;

use Cbox\Id\Pipes\Enums\RevocationStyle;

/**
 * Where and how a provider revokes a token — see {@see RevocationStyle}.
 *
 * `endpoint` may carry `{client_id}` (GitHub names the app in the path) and
 * `{refresh_token}` (HubSpot names the token in the path), and the same
 * `{parameter}` placeholders as the provider's other endpoints.
 */
readonly class PipeRevocation
{
    public function __construct(
        public string $endpoint,
        public RevocationStyle $style,
        /**
         * Revoke the refresh token rather than the access token when there is one.
         *
         * Google and Salesforce revoke the whole grant when handed the refresh token, but
         * only the one short-lived token when handed the access token — which a disconnect
         * that should end the app's access entirely would get wrong silently.
         */
        public bool $prefersRefreshToken = false,
    ) {}
}
