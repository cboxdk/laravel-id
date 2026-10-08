<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Enums;

/**
 * What the administrator brings BACK from their identity provider's screen once our
 * values are in — the shape decides which form the console shows next.
 */
enum GuideReturnKind: string
{
    /** A SAML metadata URL we fetch (and can re-fetch when their certificate rotates). */
    case Url = 'url';

    /** A SAML metadata XML file to upload or paste. */
    case Xml = 'xml';

    /** Either: the IdP offers a URL and a download. Prefer the URL. */
    case UrlOrXml = 'url_or_xml';

    /** An OIDC issuer URL plus a client ID and client secret. */
    case Oidc = 'oidc';
}
