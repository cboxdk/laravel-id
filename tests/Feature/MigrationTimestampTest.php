<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;

/**
 * Every migration has a timestamp of its own.
 *
 * The migrator runs files in basename order across every path it loads, so two files that
 * share a timestamp run in the order their NAMES sort — an accident of wording, not a
 * decision. 1.19 was built as six parallel work packages and four of them each started at
 * `2026_09_24_000100`; the order they happened to sort into was correct only by luck, and
 * a later rename of one file could have put an ALTER in front of the CREATE it depends on.
 *
 * The collisions listed here shipped in released versions and are frozen: renaming a
 * migration a deployment has already run makes the migrator run it a second time. Nothing
 * may be added to the list — give the new file the next free timestamp instead.
 */
it('gives every migration a timestamp no other migration shares', function (): void {
    $released = [
        '2026_01_01_001600', '2026_01_01_001700', '2026_01_01_001800', '2026_01_01_001900',
        '2026_01_01_002000', '2026_07_21_000100', '2026_07_25_000100', '2026_08_03_000100',
    ];

    $seen = [];

    foreach (File::allFiles(dirname(__DIR__, 2).'/database/migrations') as $file) {
        if ($file->getExtension() === 'php') {
            $seen[substr($file->getFilename(), 0, 17)][] = $file->getRelativePathname();
        }
    }

    $colliding = array_filter(
        $seen,
        fn (array $files, string $timestamp): bool => count($files) > 1 && ! in_array($timestamp, $released, true),
        ARRAY_FILTER_USE_BOTH,
    );

    expect($colliding)->toBe([]);
});
