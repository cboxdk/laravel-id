<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;

/**
 * The two limits that only one of our four engines enforces, checked before it does.
 *
 * InnoDB refuses an index key over 3072 bytes, and utf8mb4 charges four bytes a
 * character — so two 512-character URI columns are already 4096 bytes together. On
 * 2026-08-01 exactly that shipped: the `create table` succeeded on MySQL, the `add
 * index` behind it failed, and because DDL there is not transactional the table was
 * left in place with the migration UNRECORDED. Every deploy afterwards stopped on
 * "table already exists" without reaching anything queued behind it, and the repair was
 * itself a migration that therefore could not run. Production could not deploy at all.
 *
 * The engine matrix in CI would have caught it — it did, ten minutes after the tag went
 * out. This is the cheap version: it runs on sqlite in milliseconds, on the suite every
 * contributor runs before pushing, where the cost of the answer is nothing.
 *
 * A SOURCE scan, because sqlite does not store the lengths: `PRAGMA table_info` reports
 * a plain `varchar` for every string column regardless of how it was declared, so live
 * introspection on the suite's own database cannot compute a byte width at all.
 *
 * When this test says it cannot resolve a column, teach it. Do not narrow what it looks
 * at — a check that silently skips what it does not understand is how 4200 bytes got
 * through a suite that was already green.
 */

/** InnoDB's per-index key limit, in bytes. MariaDB matches it. */
const INDEX_KEY_LIMIT_BYTES = 3072;

/** MySQL caps identifiers at 64 characters, PostgreSQL at 63. The tighter one wins. */
const IDENTIFIER_LIMIT = 63;

/**
 * Bytes a column contributes to an index key, worst case, in utf8mb4.
 *
 * Variable-length members carry a length prefix — one byte up to 255 bytes of payload,
 * two above it — which is part of the key and is exactly the detail that puts a
 * borderline index over the edge.
 */
function keyBytesFor(string $type, ?int $length): ?int
{
    return match ($type) {
        'string' => $length === null
            ? keyBytesFor('string', 255)
            : ($length * 4) + ($length * 4 <= 255 ? 1 : 2),
        'char' => ($length ?? 255) * 4,
        'boolean' => 1,
        'tinyInteger', 'unsignedTinyInteger' => 1,
        'smallInteger', 'unsignedSmallInteger' => 2,
        'mediumInteger', 'unsignedMediumInteger' => 3,
        'integer', 'unsignedInteger' => 4,
        'bigInteger', 'unsignedBigInteger', 'foreignId', 'id' => 8,
        'timestamp', 'dateTime', 'timestampTz', 'dateTimeTz' => 8,
        'date' => 3,
        'time' => 3,
        'decimal', 'float', 'double' => 8,
        // Blob-ish types cannot participate in an index without a prefix length, which
        // Laravel's fluent builder cannot express. Reported rather than costed.
        'text', 'longText', 'mediumText', 'json', 'jsonb', 'binary' => null,
        default => null,
    };
}

/**
 * @return array{tables: array<string, array<string, array{type: string, length: int|null}>>, indexes: list<array{file: string, table: string, columns: list<string>, name: string|null, kind: string}>}
 */
function scanMigrations(): array
{
    $roots = array_filter([
        dirname(__DIR__, 2).'/database/migrations',
        dirname(__DIR__, 2).'/database/migrations/access-control',
        dirname(__DIR__, 2).'/database/publishable',
    ], 'is_dir');

    $files = [];

    foreach ($roots as $root) {
        foreach (File::files($root) as $file) {
            if ($file->getExtension() === 'php') {
                $files[$file->getFilename()] = $file->getPathname();
            }
        }
    }

    // Filename order is migration order, which is what makes a later `Schema::table`
    // resolvable against the columns an earlier `Schema::create` declared.
    ksort($files);

    $tables = [];
    $indexes = [];

    foreach ($files as $filename => $path) {
        $source = (string) file_get_contents($path);

        // Strip comments so a documented example cannot be mistaken for a declaration.
        $source = (string) preg_replace('~//[^\n]*|/\*.*?\*/~s', '', $source);

        $table = null;

        foreach (preg_split('/\n/', $source) ?: [] as $line) {
            if (preg_match("/Schema::(?:create|table)\(\s*'([^']+)'/", $line, $m) === 1) {
                $table = $m[1];
                $tables[$table] ??= [];

                continue;
            }

            if ($table === null) {
                continue;
            }

            // A column declaration, with or without a length.
            if (preg_match("/\\\$(?:table|blueprint)->([a-zA-Z]+)\(\s*'([^']+)'\s*(?:,\s*(\d+))?/", $line, $m) === 1) {
                $method = $m[1];
                $name = $m[2];
                $length = isset($m[3]) ? (int) $m[3] : null;

                if (keyBytesFor($method, $length) !== null || in_array($method, ['text', 'longText', 'mediumText', 'json', 'jsonb', 'binary'], true)) {
                    $tables[$table][$name] = ['type' => $method, 'length' => $length];
                }

                // `->index()` / `->unique()` chained onto that same column.
                if (preg_match('/->(index|unique)\(\)/', $line, $chained) === 1) {
                    $indexes[] = ['file' => $filename, 'table' => $table, 'columns' => [$name], 'name' => null, 'kind' => $chained[1]];
                }

                continue;
            }

            // A standalone composite (or single-column) index declaration.
            if (preg_match("/\\\$(?:table|blueprint)->(index|unique|primary)\(\s*\[([^\]]+)\]\s*(?:,\s*'([^']+)')?/", $line, $m) === 1) {
                preg_match_all("/'([^']+)'/", $m[2], $cols);

                $indexes[] = [
                    'file' => $filename,
                    'table' => $table,
                    'columns' => $cols[1],
                    'name' => $m[3] ?? null,
                    'kind' => $m[1],
                ];
            }
        }
    }

    return ['tables' => $tables, 'indexes' => $indexes];
}

it('keeps every index key inside the limit the smallest engine enforces', function (): void {
    ['tables' => $tables, 'indexes' => $indexes] = scanMigrations();

    expect($indexes)->not->toBeEmpty('the migration scan found nothing, so this proves nothing');

    $tooWide = [];
    $unresolved = [];

    foreach ($indexes as $index) {
        $bytes = 0;

        foreach ($index['columns'] as $column) {
            $definition = $tables[$index['table']][$column] ?? null;

            if ($definition === null) {
                // Columns a dependency's migrations create are outside this package's
                // source, so they cannot be resolved here — and an index we cannot cost
                // is one we cannot vouch for. Recorded, not silently dropped.
                $unresolved[] = $index['file'].': '.$index['table'].'.'.$column;

                continue 2;
            }

            $cost = keyBytesFor($definition['type'], $definition['length']);

            if ($cost === null) {
                $tooWide[] = sprintf(
                    '%s: %s(%s) indexes a %s column, which needs a prefix length',
                    $index['file'],
                    $index['table'],
                    implode(', ', $index['columns']),
                    $definition['type'],
                );

                continue 2;
            }

            $bytes += $cost;
        }

        if ($bytes > INDEX_KEY_LIMIT_BYTES) {
            $tooWide[] = sprintf(
                '%s: %s(%s) is %d bytes in utf8mb4, over InnoDB\'s %d — the create will succeed and the index will not, leaving the migration unrecorded',
                $index['file'],
                $index['table'],
                implode(', ', $index['columns']),
                $bytes,
                INDEX_KEY_LIMIT_BYTES,
            );
        }
    }

    expect($tooWide)->toBe([]);

    // Not a failure — a statement of what this run could not vouch for, so the number
    // cannot drift upward unnoticed.
    expect(count($unresolved))->toBeLessThan(
        20,
        'too many indexes reference columns this scan cannot resolve: '.implode('; ', array_slice($unresolved, 0, 5))
    );
});

it('keeps every generated index name inside the shortest identifier limit', function (): void {
    ['indexes' => $indexes] = scanMigrations();

    $tooLong = [];

    foreach ($indexes as $index) {
        // A primary key is exempt: no grammar emits a derived name for one — MySQL calls
        // it PRIMARY and PostgreSQL names it after the table. Costing it as though
        // Laravel generated `table_col_col_primary` reports a 68-character identifier
        // that does not exist anywhere.
        if ($index['kind'] === 'primary') {
            continue;
        }

        // Laravel derives the name from table + columns + suffix when none is given.
        $name = $index['name'] ?? implode('_', [$index['table'], implode('_', $index['columns']), $index['kind']]);

        if (strlen($name) > IDENTIFIER_LIMIT) {
            $tooLong[] = sprintf('%s: %s (%d chars)', $index['file'], $name, strlen($name));
        }
    }

    expect($tooLong)->toBe([]);
});
