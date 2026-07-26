<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Saml\SamlLogoutResult;
use Cbox\Id\SamlIdp\Contracts\SamlSingleLogout;

/**
 * SAML 2.0 Single Logout on the SERVICE-PROVIDER side: verify an inbound, signed
 * `LogoutRequest` from the customer's IdP, terminate every local session for the
 * logged-out subject, and hand back the `LogoutResponse` redirect for the browser to
 * carry to the IdP.
 *
 * Named for the role deliberately. This package plays BOTH SAML roles, and
 * {@see SamlSingleLogout} is the other one — the IdP
 * half, which terminates sessions at downstream SPs. Two interfaces sharing a short
 * name across namespaces is exactly how the wrong one gets injected.
 *
 * Published as a contract so the SLO controller depends on the module's surface
 * rather than a concrete class, matching every other Federation collaborator.
 */
interface SamlSpSingleLogout
{
    /**
     * @param  array<string, string>  $query  the request query/body parameters
     *                                        (SAMLRequest|SAMLResponse, RelayState, SigAlg, Signature)
     */
    public function handle(Connection $connection, array $query): SamlLogoutResult;
}
