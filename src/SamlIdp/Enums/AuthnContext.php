<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Enums;

/**
 * SAML 2.0 authentication context class references (SAML authn-context §3). The
 * value names how the subject was authenticated in the emitted
 * `<saml:AuthnContextClassRef>`.
 */
enum AuthnContext: string
{
    case Password = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password';
    case PasswordProtectedTransport = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
    case Unspecified = 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified';
}
