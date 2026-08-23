<?php

declare(strict_types=1);

/**
 * The docs are a shipped artefact, and nothing else in this repository compiles them.
 *
 * A missing `_index.md` drops a whole folder out of the rendered navigation; missing
 * frontmatter gives a page no title and an arbitrary position; a relative link breaks
 * silently the moment somebody renames a file. None of it fails a build, because there is
 * no build — so it fails here instead.
 *
 * Required by the cboxdk package standard: topic folders, an `_index.md` in each, and
 * title/weight/description on every page.
 */
function docsFiles(): array
{
    $root = dirname(__DIR__, 2).'/docs';
    $files = [];

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root)) as $file) {
        $path = (string) $file;

        if (str_ends_with($path, '.md')) {
            $files[] = $path;
        }
    }

    sort($files);

    return $files;
}

it('gives every docs folder an index', function (): void {
    $root = dirname(__DIR__, 2).'/docs';
    $missing = [];

    foreach (new DirectoryIterator($root) as $entry) {
        if ($entry->isDot() || ! $entry->isDir()) {
            continue;
        }

        if (! file_exists($entry->getPathname().'/_index.md')) {
            $missing[] = $entry->getFilename();
        }
    }

    expect($missing)->toBe([]);
});

it('gives every docs page a title, a weight and a description', function (): void {
    $root = dirname(__DIR__, 2).'/docs';
    $incomplete = [];

    foreach (docsFiles() as $path) {
        // The docs root's own index is the entry point and carries no weight among
        // siblings it has none of.
        if ($path === $root.'/index.md') {
            continue;
        }

        $source = (string) file_get_contents($path);

        if (! str_starts_with($source, '---')) {
            $incomplete[] = str_replace($root.'/', '', $path).' (no frontmatter)';

            continue;
        }

        $frontmatter = substr($source, 0, (int) strpos($source, "\n---", 3));

        foreach (['title', 'weight', 'description'] as $key) {
            if (preg_match('/^'.$key.':\s*\S/m', $frontmatter) !== 1) {
                $incomplete[] = str_replace($root.'/', '', $path).' (no '.$key.')';
            }
        }
    }

    expect($incomplete)->toBe([]);
});

it('resolves every relative link between docs pages', function (): void {
    $root = dirname(__DIR__, 2).'/docs';
    $broken = [];

    foreach (docsFiles() as $path) {
        preg_match_all('/\]\(([^)#:]+\.md)(#[^)]*)?\)/', (string) file_get_contents($path), $matches);

        foreach ($matches[1] as $target) {
            if (realpath(dirname($path).'/'.$target) === false) {
                $broken[] = str_replace($root.'/', '', $path).' → '.$target;
            }
        }
    }

    expect($broken)->toBe([]);
});
