<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * The lifecycle of a polled authorization grant — shared by the device flow
 * (RFC 8628) and CIBA, which model the identical four states.
 *
 * Typed rather than stringly-compared because the token-mint guard IS a status
 * comparison: only {@see self::Approved} may be exchanged, and exactly once
 * ({@see self::Redeemed} closes it). A literal that drifted between the writer and
 * the guard would silently open or close that gate.
 */
enum GrantPollStatus: string
{
    /** Awaiting the user's decision; the client is polling. */
    case Pending = 'pending';

    /** The user approved; the grant may be exchanged for a token exactly once. */
    case Approved = 'approved';

    /** The user refused; polling ends with access_denied. */
    case Denied = 'denied';

    /** Already exchanged; a further poll is a replay and is refused. */
    case Redeemed = 'redeemed';
}
