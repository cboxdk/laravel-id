<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

use Cbox\Id\Kernel\Authorization\Schema\SchemaError;

/**
 * The schema does not parse, or names something it does not define, or subtracts a
 * relation from itself. Every problem found is listed, by line, not just the first.
 */
final class InvalidSchema extends AuthorizationModelException
{
    /**
     * @param  list<SchemaError>  $errors
     */
    public function __construct(public readonly array $errors)
    {
        parent::__construct(implode(' ', array_map(static fn (SchemaError $error): string => (string) $error, $errors)));
    }

    public function errorCode(): string
    {
        return 'invalid_schema';
    }
}
