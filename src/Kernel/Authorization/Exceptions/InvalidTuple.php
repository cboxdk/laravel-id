<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

/**
 * A tuple the schema does not allow — an unknown type or relation, a relation that is only
 * computed, a subject of a kind the relation does not take — or one that is malformed.
 * In a batch, `$index` is its position, and nothing in the batch was written.
 */
final class InvalidTuple extends AuthorizationModelException
{
    public function __construct(string $message, public readonly ?int $index = null, public readonly string $field = 'tuple')
    {
        parent::__construct($index === null ? $message : "Tuple {$index}: {$message}");
    }

    public function errorCode(): string
    {
        return 'invalid_tuple';
    }
}
