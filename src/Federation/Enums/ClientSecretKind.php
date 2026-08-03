<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Enums;

/**
 * What a provider means by "client secret".
 *
 * For almost everyone it is a string you paste. Apple is different in a way that changes
 * the shape of the setup form rather than just its contents: there is no secret to copy.
 * You download a `.p8` signing key once, and the "secret" is an ES256 JWT you mint from
 * it — `iss` your team id, `sub` your Services ID, `aud` Apple — with a maximum lifetime
 * of six months.
 *
 * Modelling that as a text field is what makes an Apple integration break silently half
 * a year after it was set up, on a day nobody changed anything. So it is a distinct kind:
 * the administrator gives us the key material once, and the secret is minted per token
 * request and never stored.
 */
enum ClientSecretKind: string
{
    /** A string the provider shows you once and you paste here. */
    case Value = 'value';

    /**
     * Minted by us, per request, from key material the administrator supplies.
     *
     * Nothing to rotate manually and nothing to expire, because nothing long-lived is
     * kept — the signing key is, but that is a key, not a credential with a deadline.
     */
    case SignedJwt = 'signed_jwt';
}
