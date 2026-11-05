<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

/** No session/token was issued. The host must use its existing factor/recovery flow. */
class AuthenticationStepUpRequired extends RuntimeException
{
    public function __construct(public readonly string $assessmentId)
    {
        parent::__construct('Stronger authentication is required.');
    }
}
