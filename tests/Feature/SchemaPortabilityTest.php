<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;

/**
 * Guards the one schema rule that four engines disagree about and only one of them
 * complains about out loud.
 *
 * Laravel's ULID and UUID column helpers compile to `CHAR`, and PostgreSQL implements
 * `CHAR` as `bpchar` — blank-padded. A value shorter than the declared width comes
 * back to PHP padded to it, so a strict comparison against a row's own
 * `environment_id` is false. Postgres' own `=` and `length()` strip the blanks, which
 * is why the padding is invisible from a SQL client; MySQL and MariaDB strip them on
 * retrieval, and SQLite has no fixed-width type at all. It cost 338 test failures on
 * postgres:16 and was worth a P1.
 *
 * This is a SOURCE scan rather than a schema assertion on purpose: it fails on
 * sqlite, in a fraction of a second, on the run every contributor makes — where a
 * live-schema check would only speak up in the server-engine CI job.
 */
it('never declares a blank-padded CHAR column in a migration', function (): void {
    // char(26) via the ULID helpers, char(36) via the UUID ones, and `char()` itself.
    // Use `string($column, $length)` instead: `varchar` does not pad on any supported
    // engine, and so compares exactly once PDO hands the value to PHP.
    $banned = [
        'char', 'ulid', 'ulidMorphs', 'nullableUlidMorphs', 'foreignUlid',
        'uuid', 'uuidMorphs', 'nullableUuidMorphs', 'foreignUuid',
    ];

    $offenders = [];

    // `tests/` too: the tenancy isolation tests build their own throwaway tables, and
    // a padded id there would make the guard they exercise pass for the wrong reason.
    $roots = [dirname(__DIR__, 2).'/database', dirname(__DIR__)];

    $files = array_merge(...array_map(fn (string $root): array => File::allFiles($root), $roots));

    foreach ($files as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        // Tokenised rather than grepped, so a method name written inside a comment or
        // a string — as the migration that fixed all this necessarily does — is not
        // mistaken for a call.
        $tokens = array_values(array_filter(
            PhpToken::tokenize((string) $file->getContents()),
            fn (PhpToken $token): bool => ! $token->isIgnorable(),
        ));

        foreach ($tokens as $index => $token) {
            if ($token->id !== T_OBJECT_OPERATOR && $token->id !== T_NULLSAFE_OBJECT_OPERATOR) {
                continue;
            }

            $method = $tokens[$index + 1] ?? null;

            if ($method?->id === T_STRING && in_array($method->text, $banned, true)) {
                $offenders[] = sprintf('%s:%d ->%s()', $file->getRelativePathname(), $method->line, $method->text);
            }
        }
    }

    expect($offenders)->toBe([]);
});
