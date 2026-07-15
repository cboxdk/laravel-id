<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Enums;

/**
 * SAML 2.0 NameID formats (SAML core §8.3). The backing value is the exact URN
 * emitted in the assertion's `<saml:NameID Format="…">` and advertised in the
 * IdP metadata's `NameIDFormat` elements.
 */
enum NameIdFormat: string
{
    case EmailAddress = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
    case Persistent = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    case Transient = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
    case Unspecified = 'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified';

    /**
     * Resolve a format URN to the enum, falling back to {@see self::Unspecified}
     * for an unknown or empty value rather than trusting an attacker-chosen string.
     */
    public static function fromUrnOrUnspecified(?string $urn): self
    {
        if ($urn === null || $urn === '') {
            return self::Unspecified;
        }

        return self::tryFrom($urn) ?? self::Unspecified;
    }
}
