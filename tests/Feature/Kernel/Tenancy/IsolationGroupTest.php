<?php

declare(strict_types=1);

use Symfony\Component\Finder\Finder;

/**
 * The `--group=isolation` selector must actually contain the isolation tests.
 *
 * Pest ignores a file-level `@group` docblock: membership comes from a `uses()` call or a
 * per-test `->group()`. Seventeen files declared the group in a docblock and contributed
 * NOTHING to it — including `EnvironmentIsolationTest`, the environment proof itself —
 * while `docs/core-concepts/environments.md` and `docs/core-concepts/platform-operators.md`
 * tell operators to run exactly that command as the evidence that tenants are separated.
 *
 * The command answered 34 tests when 149 belonged in it. That is worse than having no
 * selector: someone ran it, saw green, and drew a conclusion about the wrong 34.
 *
 * Checked from the SOURCE rather than by counting a run, so the assertion holds whatever
 * the runner is doing, and names the offending file rather than a bare number.
 */
it('puts every file that claims the isolation group into it', function (): void {
    $claiming = [];
    $joined = [];

    foreach (Finder::create()->files()->in(__DIR__.'/../../..')->name('*Test.php') as $file) {
        $source = (string) file_get_contents((string) $file->getRealPath());
        $name = $file->getRelativePathname();

        if (str_contains($source, '@group isolation')) {
            $claiming[] = $name;
        }

        if (str_contains($source, "group('isolation')")) {
            $joined[] = $name;
        }
    }

    // Nothing claiming the group means the sweep broke, not that the suite is tidy.
    expect(count($claiming))->toBeGreaterThan(10, 'the isolation sweep found almost nothing');

    $declaredOnly = array_values(array_diff($claiming, $joined));

    expect($declaredOnly)->toBe([], 'declare @group isolation but contribute no tests to it: '.implode(', ', $declaredOnly));
});
