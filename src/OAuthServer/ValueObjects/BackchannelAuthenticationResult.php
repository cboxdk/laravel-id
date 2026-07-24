<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * The result of beginning a CIBA flow (OpenID Connect CIBA Core §7.3).
 *
 * Two identifiers, for two different parties — keep them apart:
 *  - `authReqId` is the CLIENT's polling secret. It is the only field the
 *    backchannel endpoint returns to the client (hashed at rest), and the value
 *    the client presents at the token endpoint.
 *  - `requestId` is the internal handle the HOST's approval surface uses to
 *    approve/deny; it is NEVER returned to the client (the client must not be able
 *    to approve its own request). It is surfaced only in-process and via the
 *    `oauth.backchannel_authentication_requested` domain event.
 */
readonly class BackchannelAuthenticationResult
{
    public function __construct(
        public string $requestId,
        public string $authReqId,
        public string $subjectId,
        public int $expiresIn,
        public int $interval,
        public ?string $bindingMessage = null,
    ) {}
}
