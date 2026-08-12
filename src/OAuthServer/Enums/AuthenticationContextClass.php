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
     * The level a session with these authentication methods reached.
     *
     * @param  list<string>  $amr
     */
    public static function forAmr(array $amr): self
    {
        return array_intersect($amr, self::SECOND_FACTOR_METHODS) !== [] ? self::Aal2 : self::Aal1;
    }

    /**
     * Does a session authenticated with these methods meet this level? Aal1 is met by
     * any authenticated session; Aal2 demands one of {@see SECOND_FACTOR_METHODS}.
     *
     * @param  list<string>  $amr
     */
    public function isSatisfiedBy(array $amr): bool
    {
        return match ($this) {
            self::Aal1 => true,
            self::Aal2 => self::forAmr($amr) === self::Aal2,
        };
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
        // reason to name aal2 at all is to be able to demand it.
        if (in_array(self::Aal2->value, $requested, true)) {
            return self::Aal2;
        }

        return in_array(self::Aal1->value, $requested, true) ? self::Aal1 : null;
    }

    /**
     * Every class this server asserts — exactly what discovery advertises.
     *
     * @return list<string>
     */
    public static function values(): array
    {
        return array_map(static fn (self $case): string => $case->value, self::cases());
    }
}
