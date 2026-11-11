<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

/**
 * The one place a bearer secret's prefix is decided.
 *
 * Since v3 every secret this package mints carries `cbid_<kind>_`, so a leaked one reads as
 * a Cbox ID credential and a secret scanner can match the whole family on one root. Before
 * v3 each kind had its own short prefix (`csec_`, `rt_`, `scim_`, ...), and those secrets are
 * still out there: in every app's `CBOX_ID_CLIENT_SECRET`, in customers' IdPs, in refresh
 * tokens held by signed-in users.
 *
 * GRACE: every secret is verified by the SHA-256 of the whole plaintext, never by its
 * prefix, so the old forms keep working untouched. Nothing revokes them: a client secret
 * lives until it is rotated, a SCIM token until the customer rotates it, a refresh token
 * until it expires (its successor comes back in the new form), and the short-lived ones
 * until they lapse. {@see legacy()} names the old prefix for docs, audits and tests only;
 * no code path may branch on it.
 *
 * Kept out on purpose: `pk_live_`/`pk_test_` publishable keys (public, and checked by the
 * client SDKs), `whsec_` (the Standard Webhooks spec), customer API key prefixes (the
 * customer's) and `cid_` (an OAuth client id, not a secret).
 */
enum SecretPrefix: string
{
    case ClientSecret = 'cbid_cs_';
    case RefreshToken = 'cbid_rt_';
    case AuthorizationCode = 'cbid_ac_';
    case DeviceCode = 'cbid_dc_';
    case RegistrationAccessToken = 'cbid_reg_';
    case ScimToken = 'cbid_scim_';
    case Invitation = 'cbid_inv_';
    case MagicLink = 'cbid_ml_';
    case EmailVerification = 'cbid_evf_';
    case PasswordReset = 'cbid_pwr_';

    /** Bytes of randomness after the prefix, hex-encoded (256 bits). */
    public const RANDOM_BYTES = 32;

    /** A fresh plaintext secret of this kind: the prefix and 64 hex characters. */
    public function mint(): string
    {
        return $this->value.bin2hex(random_bytes(self::RANDOM_BYTES));
    }

    /** The prefix this kind carried before v3. Still accepted; never minted. */
    public function legacy(): string
    {
        return match ($this) {
            self::ClientSecret => 'csec_',
            self::RefreshToken => 'rt_',
            self::AuthorizationCode => 'ac_',
            self::DeviceCode => 'dvc_',
            self::RegistrationAccessToken => 'reg_',
            self::ScimToken => 'scim_',
            self::Invitation => 'inv_',
            self::MagicLink => 'ml_',
            self::EmailVerification => 'evf_',
            self::PasswordReset => 'pwr_',
        };
    }
}
