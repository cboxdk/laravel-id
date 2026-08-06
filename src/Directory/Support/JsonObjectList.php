<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Support;

/**
 * Narrows a decoded JSON value to a list of JSON objects.
 *
 * The connectors used to assert this shape with an inference-override
 * `@var array<int, array<string, mixed>>` on the decoded body — a claim about a
 * remote provider's response that nothing checked. PHPStan then reasoned about the
 * asserted type rather than the real one, so a provider returning `{"users": null}`
 * or a list with a scalar in it produced a TypeError inside the mapper rather than
 * being skipped, and static analysis could not see it coming.
 *
 * Non-object entries are dropped rather than raising: a directory page that contains
 * one malformed record should sync the rest, not fail the whole cycle.
 */
final class JsonObjectList
{
    /**
     * @return list<array<string, mixed>>
     */
    public static function from(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $objects = [];

        foreach ($value as $entry) {
            if (! is_array($entry)) {
                continue;
            }

            $object = [];
            foreach ($entry as $key => $item) {
                $object[(string) $key] = $item;
            }

            $objects[] = $object;
        }

        return $objects;
    }
}
