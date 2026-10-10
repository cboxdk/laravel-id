<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

/**
 * A consistency token that this environment did not issue — malformed, minted by another
 * environment, or naming a revision this one has not reached.
 */
final class InvalidConsistencyToken extends AuthorizationModelException
{
    public function errorCode(): string
    {
        return 'invalid_consistency_token';
    }
}
