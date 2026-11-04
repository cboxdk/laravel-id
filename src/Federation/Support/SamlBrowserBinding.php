<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Support;

use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use DOMDocument;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use OneLogin\Saml2\Utils;
use Symfony\Component\HttpFoundation\Cookie as BrowserCookie;
use Throwable;

/** Browser ownership of an AuthnRequest; the database separately enforces expiry and single use. */
class SamlBrowserBinding
{
    public function remember(string $connectionId, string $requestId): void
    {
        Cookie::queue(new BrowserCookie(
            name: self::cookieName($connectionId),
            value: $requestId,
            expire: now()->addMinutes(10),
            path: '/',
            domain: null,
            secure: true,
            httpOnly: true,
            sameSite: BrowserCookie::SAMESITE_NONE,
        ));
    }

    /** Checked before validation consumes the request; this parse establishes no trust in the assertion. */
    public function assertMatches(Request $request, string $connectionId, string $response): void
    {
        $xml = base64_decode($response, true);

        try {
            $document = is_string($xml) && $xml !== '' ? Utils::loadXML(new DOMDocument, $xml) : null;
        } catch (Throwable) {
            $document = null;
        }

        // The protocol validator rejects malformed documents and decides whether an
        // unsolicited response is allowed. Only solicited responses have a browser owner.
        $requestId = $document instanceof DOMDocument ? $document->documentElement?->getAttribute('InResponseTo') : null;

        if ($requestId === null || $requestId === '') {
            return;
        }

        $expected = $request->cookie(self::cookieName($connectionId));

        if (! is_string($expected) || $expected === '' || ! hash_equals($expected, $requestId)) {
            throw InvalidAssertion::make('SAML response does not belong to this browser');
        }
    }

    public function forget(string $connectionId): void
    {
        Cookie::queue(new BrowserCookie(
            name: self::cookieName($connectionId),
            value: null,
            expire: 1,
            path: '/',
            domain: null,
            secure: true,
            httpOnly: true,
            sameSite: BrowserCookie::SAMESITE_NONE,
        ));
    }

    private static function cookieName(string $connectionId): string
    {
        return '__Host-cbox_saml_'.hash('sha256', $connectionId);
    }
}
