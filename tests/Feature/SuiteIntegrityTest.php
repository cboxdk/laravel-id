<?php

declare(strict_types=1);

use Symfony\Component\Finder\Finder;

/**
 * A file named `*Test.php` claims that the thing it is named after is tested.
 *
 * Three files in this suite were zero bytes: `MembershipEnvironmentAccessTest`,
 * `MembershipsTest` and `ConnectionServiceTest`. All three were created empty and never
 * populated — the content went to a differently-named sibling in the same commit — and
 * nothing noticed, because a file with no tests in it cannot fail.
 *
 * That is not a tidiness problem. Somebody asking "is membership environment access
 * tested" finds a file with exactly that name, opens nothing, and concludes yes. The
 * answer happened to be yes elsewhere; the file was not evidence of it either way, and a
 * file that answers a question wrongly is worse than one that is absent.
 *
 * Checked from the SOURCE rather than by counting a run: a runner that silently skipped a
 * whole file would satisfy any assertion made about its own output.
 */
it('has no test file that contains no tests', function (): void {
    /** @var list<string> $empty */
    $empty = [];
    $scanned = 0;

    foreach (Finder::create()->files()->in(__DIR__.'/..')->name('*Test.php') as $file) {
        $scanned++;
        $source = (string) file_get_contents((string) $file->getRealPath());

        // Pest's two spellings plus PHPUnit's, so this does not quietly start ignoring a
        // file written in a style the suite already contains.
        $declaresATest = preg_match('/\b(it|test)\s*\(/', $source) === 1
            || preg_match('/function\s+test[A-Z_]/', $source) === 1;

        if (! $declaresATest) {
            $empty[] = $file->getRelativePathname();
        }
    }

    // A floor, because a sweep that found nothing to check is indistinguishable from a
    // sweep that found nothing wrong — and this one walks a directory tree, which is
    // exactly the kind of thing that silently starts pointing at the wrong place.
    expect($scanned)->toBeGreaterThan(100, 'the suite sweep found almost no test files — it is looking in the wrong directory');

    expect($empty)->toBe([], 'test files declaring no tests: '.implode(', ', $empty));
});
