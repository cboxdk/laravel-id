<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

/**
 * A check or list query names a type or relation the schema does not define. Refused
 * rather than answered "no": a typo in a check would otherwise deny everybody, silently.
 */
final class UnknownRelation extends AuthorizationModelException
{
    public static function type(string $type): self
    {
        return new self("The schema defines no type `{$type}`.");
    }

    public static function relation(string $type, string $relation): self
    {
        return new self("`{$type}` has no relation `{$relation}` in the schema.");
    }

    public function errorCode(): string
    {
        return 'unknown_relation';
    }
}
