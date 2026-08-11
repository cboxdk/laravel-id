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
    /**
     * A password, presented with NO transport protection.
     *
     * Almost never the right answer for this product and it was the one we always sent:
     * every sign-in here crosses TLS, so this understates the protection — and it was
     * emitted even for people who used a passkey and typed no password at all. A signed
     * assertion is a statement a relying party makes decisions on; a false one is worse
     * than a vague one.
     */
    case Password = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password';

    /** A password over a protected channel — what a password sign-in here actually is. */
    case PasswordProtectedTransport = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

    /**
     * Authenticated, by a method this vocabulary cannot describe.
     *
     * SAML 2.0's class list predates WebAuthn by more than a decade and has no entry for
     * a passkey. `Smartcard` and `SoftwarePKI` are close enough to be tempting and both
     * would be untrue. "Unspecified" is the one option that says exactly what we know:
     * this person authenticated, and the vocabulary has no word for how.
     */
    case Unspecified = 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified';

    /**
     * The class that honestly describes a session authenticated with these methods.
     *
     * Read from the same `amr` the OIDC side uses for `acr`, so the two protocols cannot
     * describe one sign-in differently — which they did: an id_token said aal2 for a
     * passkey while the SAML assertion for the same session said Password.
     *
     * A password present means PasswordProtectedTransport, whether or not a second factor
     * joined it. That is a real limit rather than an oversight: SAML 2.0's core classes
     * have no way to say "and also a second factor", and the widely-deployed extensions
     * for it are vendor URNs that mean nothing to an SP that has not been told about them.
     * An SP that needs to know about step-up should be reading it from an attribute we
     * mapped for it, not inferring it from a class reference that cannot carry it.
     *
     * @param  list<string>  $amr
     */
    public static function forAmr(array $amr): self
    {
        return in_array('pwd', $amr, true)
            ? self::PasswordProtectedTransport
            : self::Unspecified;
    }
}
