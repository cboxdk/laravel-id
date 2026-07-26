<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Enums;

/**
 * The SAML 2.0 protocol bindings this IdP speaks (SAML bindings §3.4, §3.5). The
 * backing value is the exact URN published in metadata's `Binding` attribute.
 *
 * The binding a message ARRIVES on decides how it is authenticated and how it is
 * answered: HTTP-Redirect carries a detached query signature and is answered with
 * a signed redirect; HTTP-POST carries an enveloped XML-DSig and is answered with
 * a self-submitting form. Mixing the two is what made POST-binding logout — which
 * Okta and ADFS prefer — fail.
 */
enum SamlBinding: string
{
    case Redirect = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

    case Post = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
}
