<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;

/**
 * The new schema is valid on its own but would strand tuples already written: it drops a
 * type or relation they are on, or no longer allows the kind of subject they name. Delete
 * those tuples first — a schema change never deletes access silently.
 */
final class SchemaConflict extends AuthorizationModelException implements HasSourceMessage
{
    use CarriesSourceMessage;

    /**
     * @param  list<array{resource_type: string, relation: string, subject: string, tuples: int}>  $stranded
     */
    public function __construct(public readonly array $stranded)
    {
        $parts = array_map(
            static fn (array $group): string => "{$group['tuples']} tuple(s) give `{$group['subject']}` `{$group['relation']}` on `{$group['resource_type']}`",
            array_slice($stranded, 0, 10),
        );

        $messages = array_map(static fn (array $group): SourceMessage => new SourceMessage(':tuples tuple(s) give `:subject` `:relation` on `:resource_type`', $group), array_slice($stranded, 0, 10));
        $this->withSourceMessage(new SourceMessage(count($stranded) > 10 ? 'The new schema would strand existing tuples — delete them first: :messages; and more.' : 'The new schema would strand existing tuples — delete them first: :messages.', ['messages' => $messages]));
        parent::__construct('The new schema would strand existing tuples — delete them first: '.implode('; ', $parts).(count($stranded) > 10 ? '; and more.' : '.'));
    }

    public function errorCode(): string
    {
        return 'schema_conflict';
    }
}
