<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * Internal signal that a consumed refresh token was presented again (theft). It
 * carries the family id so the caller can revoke the whole lineage *after* the
 * rotation transaction unwinds — revoking inside the transaction would be rolled
 * back by the very exception that reports the reuse.
 */
class RefreshTokenReuse extends RuntimeException
{
    public function __construct(public readonly string $familyId)
    {
        parent::__construct('refresh token reuse detected');
    }
}
