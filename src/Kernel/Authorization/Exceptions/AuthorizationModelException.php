<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

use RuntimeException;

/**
 * A fine-grained authorization request the model refuses — a schema that does not hold
 * together, a tuple the schema does not allow, a check too deep to answer. Each carries a
 * stable machine code, so a door (REST, MCP, a console form) can answer with it unchanged.
 */
abstract class AuthorizationModelException extends RuntimeException
{
    abstract public function errorCode(): string;
}
