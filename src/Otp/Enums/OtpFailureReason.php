<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Enums;

use Cbox\Id\Otp\ValueObjects\OtpResult;

/**
 * Why a verification did not succeed. Deliberately coarse: {@see Invalid} covers
 * BOTH a wrong code and an unknown/consumed challenge, so the reason never lets a
 * caller enumerate which recipients or challenges exist. {@see Expired} and
 * {@see Locked} are only ever returned to a caller that already presented a valid
 * challenge id (it is not an enumeration signal), so a host can still tell the
 * user to request a fresh code. {@see RateLimited} reflects the global verify
 * throttle, not any per-recipient state.
 */
enum OtpFailureReason: string
{
    /** Verification succeeded — carried on a successful {@see OtpResult}. */
    case None = 'none';

    /** Wrong code, or no matching live challenge. Uniform across both. */
    case Invalid = 'invalid';

    /** A held challenge whose TTL has elapsed. */
    case Expired = 'expired';

    /** A held challenge whose attempt cap has been reached. */
    case Locked = 'locked';

    /** The global per-IP verify throttle refused this attempt. */
    case RateLimited = 'rate_limited';
}
