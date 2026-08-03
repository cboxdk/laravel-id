<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Enums;

/**
 * How a provider proves who the person is.
 *
 * The distinction is not pedantry — it decides what the connection can trust. An OIDC
 * provider returns a SIGNED `id_token`: the assertion is verifiable on its own, offline,
 * against a published key. An OAuth 2.0 provider returns only an access token, and the
 * identity has to be fetched from a userinfo-shaped endpoint afterwards — so the trust
 * rests on TLS to that endpoint and on the token having been issued to us, not on a
 * signature over the claims.
 *
 * GitHub and Discord are the reason this enum exists. Neither is an OpenID Provider:
 * there is no discovery document and no `id_token`, so the generic OIDC connection path
 * cannot reach them at all, however OAuth-shaped they look from the outside.
 */
enum FederationProtocol: string
{
    /** Discovery, `id_token`, signature verified against the issuer's JWKS. */
    case Oidc = 'oidc';

    /**
     * Authorization code for an access token, then a profile fetch.
     *
     * Weaker than OIDC by construction. Two things carry the weight in place of a
     * signature: the token was issued to OUR client id, and the profile came back over
     * TLS from the endpoint we pinned. That is enough for a sign-in button; it is not
     * enough to be treated as an assertion about anything else.
     */
    case OAuth2 = 'oauth2';

    public function usesDiscovery(): bool
    {
        return $this === self::Oidc;
    }
}
