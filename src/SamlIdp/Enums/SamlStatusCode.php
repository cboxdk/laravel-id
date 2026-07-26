<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Enums;

/**
 * SAML 2.0 status codes (SAML core §3.2.2.2). The backing value is the exact URN
 * emitted in `<samlp:StatusCode Value="…">`.
 *
 * The first four are TOP-LEVEL codes — every Response carries exactly one. The
 * rest are second-level codes, nested inside the top-level one to say precisely
 * what was wrong, which is the difference between an SP logging "the IdP said the
 * NameIDPolicy is unsatisfiable" and a user staring at an unbranded 400 page.
 */
enum SamlStatusCode: string
{
    case Success = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    case Requester = 'urn:oasis:names:tc:SAML:2.0:status:Requester';

    case Responder = 'urn:oasis:names:tc:SAML:2.0:status:Responder';

    case VersionMismatch = 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch';

    case InvalidNameIdPolicy = 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy';

    case RequestDenied = 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied';

    case AuthnFailed = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed';
}
