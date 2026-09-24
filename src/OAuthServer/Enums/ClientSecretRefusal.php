<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * Why a secret operation on a client was refused.
 *
 * Carried on the exception so a caller — and a test — can tell the refusals apart without
 * parsing a message: "this client has no secrets to rotate" and "that is its last secret"
 * throw the same class for different reasons, and a console answers them differently.
 */
enum ClientSecretRefusal: string
{
    /** A public client authenticates with PKCE alone and holds no secret. */
    case PublicClient = 'public_client';

    /** A `private_key_jwt` client authenticates with its keys; a secret would add a bearer credential. */
    case SignsAssertions = 'signs_assertions';

    /** Revoking it would leave a shared-secret client with nothing to authenticate with. */
    case LastLiveSecret = 'last_live_secret';

    /** The grace period is negative or longer than the configured ceiling. */
    case GraceOutOfRange = 'grace_out_of_range';

    /** No live secret with that id belongs to this client. */
    case UnknownSecret = 'unknown_secret';
}
