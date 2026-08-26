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

/**
 * A COLUMN MUST BE WIDE ENOUGH FOR THE ID IT NAMES.
 *
 * `legacy_login_declarations.client_id` was declared `string('client_id', 26)` — the ULID
 * width, taken from the three columns above it, which are genuinely ULIDs. A client id is
 * not: `ClientRegistryService` mints `'cid_'.Str::ulid()`, so every value is thirty
 * characters. PostgreSQL refused the insert (`22001`), MySQL in strict mode refused it and
 * without strict mode truncated the id to one that matches no client, and SQLite ignores
 * declared widths so nothing said anything at all.
 *
 * The engine matrix did not catch it either, and that is the part worth remembering: the
 * one test that writes this row passed `'client-a'` as the client id. A fixture shaped
 * unlike the data it stands for takes the engines' opinion out of the run.
 *
 * The floor is DERIVED from the mint rather than written down here, so a change to the
 * prefix moves this test with it instead of leaving a number behind that used to be right.
 */
it('never declares an id column too narrow for the id it holds', function (): void {
    $registry = (string) File::get(dirname(__DIR__, 2).'/src/OAuthServer/ClientRegistryService.php');

    expect(preg_match("/'client_id' => '([a-z]+_)'/", $registry, $mint))->toBe(
        1,
        'could not read the client id prefix off ClientRegistryService — has it moved?',
    );

    // The prefix plus a ULID. Named rather than inlined, because 26 is the number the
    // sweep above is about and this is the number it is not.
    $widths = [
        'client_id' => strlen($mint[1]) + 26,
    ];

    $offenders = [];

    $roots = [dirname(__DIR__, 2).'/database', dirname(__DIR__)];

    $files = array_merge(...array_map(fn (string $root): array => File::allFiles($root), $roots));

    foreach ($files as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $source = (string) $file->getContents();

        foreach ($widths as $column => $minimum) {
            preg_match_all("/->string\\(\\s*'{$column}'\\s*,\\s*(\\d+)\\s*\\)/", $source, $found, PREG_SET_ORDER);

            foreach ($found as $declaration) {
                if ((int) $declaration[1] < $minimum) {
                    $offenders[] = sprintf(
                        '%s declares %s at %d, and an id of that kind is %d characters',
                        $file->getRelativePathname(),
                        $column,
                        (int) $declaration[1],
                        $minimum,
                    );
                }
            }
        }
    }

    expect($offenders)->toBe([], implode("\n", $offenders));
});
