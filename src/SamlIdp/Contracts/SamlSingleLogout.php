<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Contracts;

use Cbox\Id\SamlIdp\Exceptions\InvalidLogoutRequest;
use Cbox\Id\SamlIdp\ValueObjects\LogoutMessage;
use Cbox\Id\SamlIdp\ValueObjects\SamlLogoutOutcome;

/**
 * Processes an SP-initiated SAML Single Logout at this IdP: verifies the signed
 * `LogoutRequest` against the registered SP's certificate and produces a signed
 * `LogoutResponse` addressed back to that SP's SLO endpoint. Deny-by-default — an
 * unknown SP, an unsigned/invalid request, or an SP with no SLO endpoint is refused.
 */
interface SamlSingleLogout
{
    /**
     * @throws InvalidLogoutRequest
     */
    public function process(LogoutMessage $message): SamlLogoutOutcome;
}
