<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;

/**
 * A check or list query names a type or relation the schema does not define. Refused
 * rather than answered "no": a typo in a check would otherwise deny everybody, silently.
 */
final class UnknownRelation extends AuthorizationModelException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public static function type(string $type): self
    {
        return (new self("The schema defines no type `{$type}`."))->withSourceMessage(new SourceMessage('The schema defines no type `:type`.', ['type' => $type]));
    }

    public static function relation(string $type, string $relation): self
    {
        return (new self("`{$type}` has no relation `{$relation}` in the schema."))->withSourceMessage(new SourceMessage('`:type` has no relation `:relation` in the schema.', ['type' => $type, 'relation' => $relation]));
    }

    public function errorCode(): string
    {
        return 'unknown_relation';
    }
}
