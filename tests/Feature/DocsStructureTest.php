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

/**
 * Resolve a repo-relative path the way Linux does, whatever the host filesystem thinks.
 *
 * Walks it segment by segment against `scandir`, because the obvious `realpath()` and
 * `file_exists()` are both case-INSENSITIVE on macOS: a link to `Quickstart.md` resolves
 * on the laptop that wrote it and 404s on the box that renders the site.
 */
function docsPathExists(string $repoRoot, string $relative): bool
{
    $current = $repoRoot;

    foreach (explode('/', $relative) as $segment) {
        $entries = @scandir($current);

        if ($entries === false || ! in_array($segment, $entries, true)) {
            return false;
        }

        $current .= '/'.$segment;
    }

    return true;
}

/**
 * A docs link that points at nothing breaks by RENAME, silently, in a directory nothing
 * else compiles — so it fails here instead.
 *
 * Resolved TEXTUALLY and then checked case-sensitively, rather than with `realpath()`.
 * realpath answers two questions wrongly here, and both make this pass on the machine
 * that wrote the link and fail on the one that publishes it: the case problem above, and
 * that it follows a path straight out of the repository. A `../../../other-repo/docs/…`
 * link resolves for whoever has that repo checked out beside this one and for nobody
 * else — which is exactly what the sibling sweep in cbox-id caught the first time it ran
 * in CI. Links that leave `docs/` but stay in the repo (`../UPGRADING.md`) are fine.
 */
it('resolves every relative link between docs pages', function (): void {
    $repoRoot = dirname(__DIR__, 2);
    $broken = [];

    foreach (docsFiles() as $path) {
        $directory = str_replace($repoRoot.'/', '', dirname($path));

        preg_match_all('/\]\(([^)#:]+\.md)(#[^)]*)?\)/', (string) file_get_contents($path), $matches);

        foreach ($matches[1] as $target) {
            $segments = [];
            $escapes = false;

            foreach (explode('/', $directory.'/'.$target) as $segment) {
                if ($segment === '' || $segment === '.') {
                    continue;
                }

                if ($segment === '..') {
                    if ($segments === []) {
                        $escapes = true;

                        break;
                    }

                    array_pop($segments);

                    continue;
                }

                $segments[] = $segment;
            }

            if ($escapes || ! docsPathExists($repoRoot, implode('/', $segments))) {
                $broken[] = str_replace($repoRoot.'/docs/', '', $path).' → '.$target;
            }
        }
    }

    expect($broken)->toBe([]);
});
