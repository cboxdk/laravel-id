<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Support;

use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;

/**
 * The shape a federation START URL must have before this platform will send a person's
 * browser to it.
 *
 * Distinct from {@see SafeFederationUrl}, which guards the endpoints the SERVER fetches
 * and so blocks private and reserved addresses. This one guards the endpoints the BROWSER
 * is sent to — an organization's OIDC `authorization_endpoint` or SAML `idp_sso_url` —
 * where the whole point is that the host may be anybody's. Blocking hosts here would ban
 * every legitimate IdP; what can be checked is the shape.
 *
 * What that buys, given the destination is tenant-chosen by design:
 *
 *   - **https only.** A start URL over `http` puts the SAMLRequest, the RelayState and
 *     the eventual redirect back through a network attacker in the clear, and hands them
 *     a page the person believes is their employer's sign-in.
 *   - **no `javascript:`, `data:` or anything else.** `Location:` will not follow those
 *     in a modern browser, but the same configured string is what a console renders as a
 *     link and what a future non-redirect caller might interpolate.
 *   - **no embedded credentials.** `https://id.okta.com@evil.example/` reads as Okta to
 *     a person scanning the URL bar and resolves to `evil.example`.
 *   - **no fragment.** Everything after `#` never reaches the server, so a start URL that
 *     carries one is either a mistake or an attempt to smuggle something past a log.
 *
 * It does NOT claim to stop an administrator pointing their own organization at a bad
 * IdP: that is their connection, their members, and their decision. It stops that
 * connection being usable as an open-redirect primitive with this platform's domain on
 * the front of it.
 */
class BrowserStartUrl
{
    public static function assert(string $url, string $field): string
    {
        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['host']) || $parts['host'] === '') {
            throw UnsafeFederationUrl::make("[{$field}] is not a valid absolute URL");
        }

        if (($parts['scheme'] ?? null) !== 'https') {
            throw UnsafeFederationUrl::make("[{$field}] must be an https URL");
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw UnsafeFederationUrl::make("[{$field}] must not carry credentials");
        }

        if (isset($parts['fragment'])) {
            throw UnsafeFederationUrl::make("[{$field}] must not carry a fragment");
        }

        return $url;
    }
}
