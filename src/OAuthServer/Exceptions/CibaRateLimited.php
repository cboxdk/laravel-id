<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * Too many backchannel requests for one person, or from one client for one hint, in the
 * window. The request is not filed and nobody is prompted; the client is told when it may
 * ask again.
 */
class CibaRateLimited extends RuntimeException
{
    public function __construct(public readonly int $retryAfter)
    {
        parent::__construct('too many backchannel authentication requests; try again later');
    }
}
