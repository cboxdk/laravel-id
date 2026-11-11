<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * The OIDC authentication context class references (`acr`) this IdP asserts, and the
 * ONE place that decides which `amr` methods count as a second factor.
 *
 * Discovery advertises these (`acr_values_supported`), the `/authorize` endpoint
 * honours a requested `acr_values`, and the id_token stamps the resulting `acr`. All
 * three previously carried their own copy of the "what is a second factor?" list, or
 * carried none at all — so the server could advertise `aal2`, authorize a
 * password-only session, and hand back an `aal1` id_token. Keeping the predicate here
 * means the advertisement, the gate and the claim cannot drift apart.
 */
enum AuthenticationContextClass: string
{
    /** A single authentication factor (e.g. a password) was used. */
    case Aal1 = 'urn:cbox-id:aal1';

    /** A second factor was used at login. */
    case Aal2 = 'urn:cbox-id:aal2';

    /**
     * Phishing-resistant: a WebAuthn assertion (a passkey or a security key) with user
     * verification. The credential is bound to the origin by the browser, so there is no
     * code a look-alike page can ask the person to read out. A time-based code, a texted
     * code, an emailed code and a recovery code never reach it, whatever else is in `amr`.
     *
     * A vendor URN like its siblings. It sits ABOVE {@see self::Aal2}: every session that
     * reaches it also reaches `aal2` ({@see self::reaches()}).
     *
     * A session can always be ASKED whether it reached this ({@see self::isSatisfiedBy()}).
     * Whether a token's `acr` SAYS so is the host's choice
     * (`cbox-id.oauth.acr.phishing_resistant`, off by default): a relying party that
     * compares `acr` to `urn:cbox-id:aal2` as a string would otherwise start refusing
     * everybody who signs in with a passkey on the day this shipped.
     */
    case PhishingResistant = 'urn:cbox-id:phr';

    /**
     * The `amr` methods that constitute a second authentication factor.
     *
     * `webauthn` stays in the list although no door writes it any more: it is recorded on
     * live sessions and inside issued tokens, and removing the string would quietly
     * downgrade those to `aal1` halfway through their life. See {@see AuthMethod}.
     *
     * @var list<string>
     */
    private const SECOND_FACTOR_METHODS = [
        AuthMethod::MultiFactor->value,
        AuthMethod::OneTimePassword->value,
        AuthMethod::Passkey->value,
        'webauthn',
    ];

    /**
     * The assurance LEVEL a session with these authentication methods reached: `aal1` or
     * `aal2`, never {@see self::PhishingResistant}. Use {@see self::strongestFor()} for the
     * strongest class, and {@see self::assertedFor()} for what a token should say.
     *
     * @param  list<string>  $amr
     */
    public static function forAmr(array $amr): self
    {
        return array_intersect($amr, self::SECOND_FACTOR_METHODS) !== [] ? self::Aal2 : self::Aal1;
    }

    /**
     * The strongest class these methods reached, phishing-resistant included.
     *
     * @param  list<string>  $amr
     */
    public static function strongestFor(array $amr): self
    {
        return self::PhishingResistant->isSatisfiedBy($amr) ? self::PhishingResistant : self::forAmr($amr);
    }

    /**
     * The class a token's `acr` states for these methods: the strongest this deployment
     * asserts ({@see self::asserted()}).
     *
     * @param  list<string>  $amr
     */
    public static function assertedFor(array $amr): self
    {
        return self::assertsPhishingResistant() ? self::strongestFor($amr) : self::forAmr($amr);
    }

    /**
     * Does a session authenticated with these methods meet this class? Aal1 is met by
     * any authenticated session; Aal2 demands one of {@see SECOND_FACTOR_METHODS}.
     *
     * PhishingResistant demands a WebAuthn assertion WITH user verification: `passkey`
     * says the credential was used, and `mfa` beside it says the authenticator verified
     * the person ({@see AuthMethod::forPasskey()} leaves `mfa` out when it did not). The
     * legacy `webauthn` string does not count: nothing recorded whether those assertions
     * were user-verified.
     *
     * A passkey ADDED to a session that already holds `mfa` from a one-time code is read
     * as verified. A door that does not require user verification must therefore not
     * record `passkey` on a session it is stepping up; every door of this package's
     * verifier requires it unless `cbox-id.webauthn.user_verification` is turned off.
     *
     * @param  list<string>  $amr
     */
    public function isSatisfiedBy(array $amr): bool
    {
        return match ($this) {
            self::Aal1 => true,
            self::Aal2 => self::forAmr($amr) === self::Aal2,
            self::PhishingResistant => in_array(AuthMethod::Passkey->value, $amr, true)
                && in_array(AuthMethod::MultiFactor->value, $amr, true),
        };
    }

    /** A higher class meets a lower one: phishing-resistant meets aal2, aal2 meets aal1. */
    public function reaches(self $required): bool
    {
        return $this->rank() >= $required->rank();
    }

    /**
     * The STRONGEST level named in a space-delimited OIDC `acr_values` request, or
     * null when the request names none this server asserts. Unknown values are
     * ignored rather than refused: `acr_values` is an ordered list of acceptable
     * classes, so a client may legitimately list ones another IdP understands.
     */
    public static function fromRequest(?string $acrValues): ?self
    {
        if (! is_string($acrValues) || trim($acrValues) === '') {
            return null;
        }

        $requested = array_values(array_filter(explode(' ', trim($acrValues)), static fn (string $v): bool => $v !== ''));

        // Strongest-wins: a client asking for "aal1 aal2" will accept either, but the
        // reason to name aal2 at all is to be able to demand it. Only classes this
        // deployment asserts: a class no token can state must not become a requirement
        // no token can meet.
        $strongest = null;

        foreach (self::asserted() as $class) {
            if (in_array($class->value, $requested, true) && ($strongest === null || $class->rank() > $strongest->rank())) {
                $strongest = $class;
            }
        }

        return $strongest;
    }

    /**
     * Every class this server asserts — exactly what discovery advertises.
     *
     * @return list<string>
     */
    public static function values(): array
    {
        return array_map(static fn (self $case): string => $case->value, self::asserted());
    }

    /**
     * The classes this deployment states in a token and honours in a request:
     * {@see self::PhishingResistant} only where the host turned it on.
     *
     * @return list<self>
     */
    public static function asserted(): array
    {
        return self::assertsPhishingResistant()
            ? [self::Aal1, self::Aal2, self::PhishingResistant]
            : [self::Aal1, self::Aal2];
    }

    private static function assertsPhishingResistant(): bool
    {
        return config('cbox-id.oauth.acr.phishing_resistant', false) === true;
    }

    private function rank(): int
    {
        return match ($this) {
            self::Aal1 => 1,
            self::Aal2 => 2,
            self::PhishingResistant => 3,
        };
    }
}
