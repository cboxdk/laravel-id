<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

/**
 * The environment has no authorization schema yet, so there is nothing a tuple could be
 * checked against. Define one first.
 */
final class SchemaNotDefined extends AuthorizationModelException
{
    public function __construct()
    {
        parent::__construct('This environment has no authorization schema yet. Define one first.');
    }

    public function errorCode(): string
    {
        return 'schema_not_defined';
    }
}
