<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Enums;

/**
 * SAML 2.0 NameID formats (SAML core §8.3). The backing value is the exact URN
 * emitted in the assertion's `<saml:NameID Format="…">` and advertised in the
 * IdP metadata's `NameIDFormat` elements.
 *
 * SAML 2.0 does NOT mint a fresh URN for every format: §8.3.1 (Unspecified) and
 * §8.3.2 (Email Address) both point back at the SAML 1.1 identifiers, and only the
 * formats 2.0 introduced (persistent, transient, entity, kerberos) carry a `2.0`
 * prefix. `urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified` does not exist in
 * any specification — an SP sending the real thing must be answered, not refused.
 */
enum NameIdFormat: string
{
    case EmailAddress = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
    case Persistent = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    case Transient = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
    case Unspecified = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

    /**
     * SAML 1.0's spelling of Unspecified. Identical in meaning to the 1.1 URN that
     * SAML 2.0 §8.3.1 names, and still what ADFS in SAML 1.x compatibility mode and
     * a number of OpenSAML-based SPs put in their `NameIDPolicy`. Accepted on input;
     * never published or emitted — {@see self::Unspecified} is the canonical URN.
     */
    public const UNSPECIFIED_SAML_1_0 = 'urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified';

    /**
     * The format a `NameIDPolicy/@Format` names, or null when the URN is not one
     * this IdP knows — the caller MUST refuse an unknown one rather than coerce it,
     * because coercing means labelling a value with a format the SP did not ask for.
     *
     * Both spellings of "unspecified" normalise onto {@see self::Unspecified}: they
     * mean the same thing ("IdP, you choose"), so treating them differently would
     * refuse a conformant SP over a legacy URN prefix.
     */
    public static function tryFromPolicyUrn(string $urn): ?self
    {
        if ($urn === self::UNSPECIFIED_SAML_1_0) {
            return self::Unspecified;
        }

        return self::tryFrom($urn);
    }

    /**
     * Resolve a format URN to the enum, falling back to {@see self::Unspecified}
     * for an unknown or empty value rather than trusting an attacker-chosen string.
     */
    public static function fromUrnOrUnspecified(?string $urn): self
    {
        if ($urn === null || $urn === '') {
            return self::Unspecified;
        }

        return self::tryFromPolicyUrn($urn) ?? self::Unspecified;
    }
}
