<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * How a client proves itself at the token endpoint (RFC 7591 `token_endpoint_auth_method`).
 *
 * STORED, NOT INFERRED. This used to be derived on readback from the shape of the row —
 * public means `none`, a JWK Set means `private_key_jwt`, anything else means
 * `client_secret_basic` — which is right about capability and wrong about fact. A client
 * that registered `client_secret_post` read back as `client_secret_basic`, so the RFC 7592
 * management document told it to authenticate one way while it had registered another;
 * the two secret methods are indistinguishable from the row because both are "has a
 * secret", and inference cannot recover a choice nothing wrote down.
 */
enum TokenEndpointAuthMethod: string
{
    /** A public client: PKCE only, no credential (RFC 7591 §2). */
    case None = 'none';

    /** The shared secret in an HTTP Basic header — the OAuth 2.0 default. */
    case ClientSecretBasic = 'client_secret_basic';

    /** The shared secret in the request body. */
    case ClientSecretPost = 'client_secret_post';

    /** A signed assertion proving the private half of a registered JWK Set (RFC 7523). */
    case PrivateKeyJwt = 'private_key_jwt';

    /**
     * Whether this method authenticates with a shared secret at all.
     *
     * Neither `none` nor `private_key_jwt` does: one holds no credential, the other holds
     * a key. Asked so a management update that moves a client INTO a secret method knows
     * it must mint one — a transition from `private_key_jwt` used to leave the client with
     * a method it had no credential for.
     */
    public function usesSharedSecret(): bool
    {
        return $this === self::ClientSecretBasic || $this === self::ClientSecretPost;
    }
}
