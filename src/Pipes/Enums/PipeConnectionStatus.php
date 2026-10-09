<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Enums;

/**
 * Where a person's connection to a third-party account stands.
 *
 * Two states, because there are only two things an app can do about a connection: use
 * it, or send the person back through the provider's consent screen. A connection that
 * was disconnected is not a third state — it is deleted, so "connected" and "has a row"
 * are the same question.
 */
enum PipeConnectionStatus: string
{
    /** The stored tokens work, or can be refreshed into tokens that do. */
    case Active = 'active';

    /**
     * The provider refused the refresh token (revoked, expired, or the person removed the
     * app on the provider's side), or the access token expired and there was nothing to
     * refresh it with. Only the person can fix this, by connecting again.
     */
    case NeedsReauth = 'needs_reauth';
}
