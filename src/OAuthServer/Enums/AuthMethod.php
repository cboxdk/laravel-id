<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * The `amr` values this IdP puts on a session, and the one place they are spelled.
 *
 * WHY AN ENUM RATHER THAN STRINGS AT EACH DOOR. Every door that authenticates somebody
 * writes an `amr`, and a relying party gating on it — `amr.includes('passkey')` is the
 * common shape — sees whatever that particular door happened to type. The hosted passkey
 * flow wrote `passkey`; the embedded one wrote `webauthn`. Same credential, same person,
 * two answers, and an RP correctly implemented against one of them locks out everybody who
 * used the other. There is nothing to notice in review, because both strings look right.
 *
 * REGISTERED VALUES TRAVEL ALONGSIDE THE VENDOR ONE. RFC 8176 registers `pwd`, `otp`,
 * `mfa` and `pop`; it registers nothing for WebAuthn, which is why `passkey` exists here at
 * all. {@see forPasskey()} emits the vendor value AND the registered ones, so an integration
 * written against the registry works without knowing anything about us.
 */
enum AuthMethod: string
{
    /** RFC 8176: a password. */
    case Password = 'pwd';

    /** RFC 8176: a one-time password, which the RFC defines as covering RFC 6238 TOTP. */
    case OneTimePassword = 'otp';

    /** RFC 8176: more than one factor was used. */
    case MultiFactor = 'mfa';

    /** RFC 8176: proof of possession of a key. The honest registered value for a passkey. */
    case ProofOfPossession = 'pop';

    /** Vendor: a WebAuthn credential. The registry has nothing for this. */
    case Passkey = 'passkey';

    /**
     * The methods a passkey login used.
     *
     * `pop` rather than `swk`/`hwk`: we cannot tell a software-backed credential from a
     * hardware one without attestation, and this server asks for none. `mfa` because user
     * verification was required at the door, so possession and something the person knows
     * or is were both proved.
     *
     * @return list<string>
     */
    public static function forPasskey(): array
    {
        return [self::Passkey->value, self::ProofOfPossession->value, self::MultiFactor->value];
    }

    /**
     * The methods a password followed by a time-based code used.
     *
     * `otp` is the registered value that names what actually happened and was the one
     * missing: the TOTP path recorded `['pwd','mfa']`, so an RP reading the registry saw a
     * second factor of no stated kind, while the emailed-code path recorded `['pwd','otp']`
     * with no `mfa` — two second factors, neither describable by one rule.
     *
     * @return list<string>
     */
    public static function forSecondFactorCode(): array
    {
        return [self::Password->value, self::OneTimePassword->value, self::MultiFactor->value];
    }

    /**
     * The methods a password followed by a recovery code used.
     *
     * No `otp`: a recovery code is a look-up secret, not a one-time password, and the
     * registry has no value for one. `mfa` is true and is what an RP gates on.
     *
     * @return list<string>
     */
    public static function forRecoveryCode(): array
    {
        return [self::Password->value, self::MultiFactor->value];
    }
}
