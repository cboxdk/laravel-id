<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * What became of one attempt to deliver a logout token.
 */
enum LogoutDeliveryStatus: string
{
    /** The relying party answered 2xx (§2.8 permits 200 and, in practice, 204). */
    case Delivered = 'delivered';

    /** Worth trying again: the connection failed, timed out, or the RP answered 5xx/408/429. */
    case Retry = 'retry';

    /** Trying again cannot help: the RP refused the token, or the URI is not one we will call. */
    case Rejected = 'rejected';

    /** Nothing to do: the client is gone, or no longer has a back-channel logout URI. */
    case Skipped = 'skipped';
}
