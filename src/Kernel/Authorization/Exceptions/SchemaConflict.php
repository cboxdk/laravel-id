<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

/**
 * The new schema is valid on its own but would strand tuples already written: it drops a
 * type or relation they are on, or no longer allows the kind of subject they name. Delete
 * those tuples first — a schema change never deletes access silently.
 */
final class SchemaConflict extends AuthorizationModelException
{
    /**
     * @param  list<array{resource_type: string, relation: string, subject: string, tuples: int}>  $stranded
     */
    public function __construct(public readonly array $stranded)
    {
        $parts = array_map(
            static fn (array $group): string => "{$group['tuples']} tuple(s) give `{$group['subject']}` `{$group['relation']}` on `{$group['resource_type']}`",
            array_slice($stranded, 0, 10),
        );

        parent::__construct('The new schema would strand existing tuples — delete them first: '.implode('; ', $parts).(count($stranded) > 10 ? '; and more.' : '.'));
    }

    public function errorCode(): string
    {
        return 'schema_conflict';
    }
}
