<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

/**
 * The result of processing an inbound `LogoutRequest`: the `NameID` the SP asked to
 * log out (verified to come from a signed request by a registered SP), and the
 * fully-formed, signed redirect URL that returns a `LogoutResponse` to the SP's SLO
 * endpoint. The controller revokes the session and 302s to `redirectUrl`.
 */
final readonly class SamlLogoutOutcome
{
    public function __construct(
        public string $nameId,
        public string $redirectUrl,
    ) {}
}
