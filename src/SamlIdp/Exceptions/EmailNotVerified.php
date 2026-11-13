<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Exceptions;

use Cbox\Id\SamlIdp\ValueObjects\SamlError;

/**
 * The IdP refused to assert this subject to this service provider because the SP would
 * receive the subject's email address — as the NameID or as a mapped attribute — and
 * that address has not been verified. A signed assertion is a statement relying parties
 * act on, and most of them key accounts by the email in it; the IdP does not vouch for
 * an address nobody confirmed.
 *
 * A subclass of {@see SubjectNotPermitted} (and so of {@see InvalidAuthnRequest}): a
 * host that already catches either around `issueResponse()` answers the SP with this
 * exception's {@see SamlError} as a signed `Responder` / `RequestDenied` Response with no
 * change. A host that wants to tell the person to confirm their address first catches
 * this narrower type, as the package's own SSO endpoint does.
 */
class EmailNotVerified extends SubjectNotPermitted
{
    public static function forServiceProvider(SamlError $error): self
    {
        $exception = new self('invalid AuthnRequest: the service provider would receive an email address the subject has not verified');
        $exception->reportAs($error);

        return $exception;
    }
}
