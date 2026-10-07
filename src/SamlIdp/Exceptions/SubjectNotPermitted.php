<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Exceptions;

use Cbox\Id\SamlIdp\ValueObjects\SamlError;

/**
 * The IdP refused to assert this subject to this service provider: the SP is owned by an
 * organization and the subject is not an active member of it.
 *
 * A subclass of {@see InvalidAuthnRequest} on purpose. Hosts already catch that type
 * around `issueResponse()` (a replayed request lands there too) and answer the SP with
 * its {@see SamlError()}, so this refusal reaches the SP as a signed `Responder` /
 * `RequestDenied` Response on its own ACS with no host change — while a host that wants
 * to show the person a friendlier page can catch this narrower type first.
 */
class SubjectNotPermitted extends InvalidAuthnRequest
{
    public static function notAMember(SamlError $error): self
    {
        $exception = new self('invalid AuthnRequest: the subject is not an active member of the organization that owns this service provider');
        $exception->reportAs($error);

        return $exception;
    }
}
