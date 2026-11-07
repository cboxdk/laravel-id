<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;

/**
 * A consistency token that this environment did not issue — malformed, minted by another
 * environment, or naming a revision this one has not reached.
 */
final class InvalidConsistencyToken extends AuthorizationModelException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public function errorCode(): string
    {
        return 'invalid_consistency_token';
    }
}
