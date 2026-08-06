<?php

declare(strict_types=1);

use Cbox\Id\Organization\Enums\OrganizationStatus;

/**
 * The access decision has to live on the enum, and it has to stay exhaustive.
 *
 * A consuming app shipped a live security bug because neither was true: `Deleted`
 * was written by its console, the enum said nothing about what that meant, and the
 * app's own gate tested `!== Suspended`. A "deleted" organization went on
 * authenticating its members, consenting, and minting tokens.
 */
it('revokes access for every status except Active', function (): void {
    expect(OrganizationStatus::Active->revokesAccess())->toBeFalse()
        ->and(OrganizationStatus::Suspended->revokesAccess())->toBeTrue()
        // The case that caused the incident: a soft-delete marker is a
        // revocation, not a bookkeeping flag.
        ->and(OrganizationStatus::Deleted->revokesAccess())->toBeTrue();
});

/**
 * The guard that outlives this file.
 *
 * `revokesAccess()` is an exhaustive `match` with no `default`, so a case added
 * later fails PHPStan at level max (`match.unhandled`) instead of silently
 * defaulting to "allowed" — which is exactly how `Deleted` slipped through. PHPStan
 * cannot be run from inside the suite, so the property is asserted structurally:
 * the arms are read out of the source, and every case the enum declares must appear
 * among them.
 *
 * If this fails because you added a case, the fix is to handle it in the match — not
 * to add a `default`, and not to relax this test.
 */
it('decides exhaustively, with no default arm to absorb a new case', function (): void {
    $method = new ReflectionMethod(OrganizationStatus::class, 'revokesAccess');

    $file = $method->getFileName();
    $start = $method->getStartLine();
    $end = $method->getEndLine();

    expect($file)->toBeString()
        ->and($start)->toBeInt()
        ->and($end)->toBeInt();

    /** @var string $file */
    /** @var int $start */
    /** @var int $end */
    $source = implode("\n", array_slice(
        explode("\n", (string) file_get_contents($file)),
        $start - 1,
        $end - $start + 1,
    ));

    // Tokenised rather than grepped so the word "default" inside the docblock that
    // explains why there is no default arm is not mistaken for one.
    $tokens = array_values(array_filter(
        PhpToken::tokenize('<?php '.$source),
        fn (PhpToken $token): bool => ! $token->isIgnorable(),
    ));

    $arms = [];
    $hasMatch = false;

    foreach ($tokens as $index => $token) {
        if ($token->id === T_MATCH) {
            $hasMatch = true;
        }

        if ($token->id === T_DEFAULT) {
            throw new RuntimeException(
                'OrganizationStatus::revokesAccess() grew a `default` arm. That is the one thing it must not have: '
                .'a status added later would inherit "access allowed" silently instead of failing static analysis.',
            );
        }

        // `self::Active` / `OrganizationStatus::Active`
        if ($token->id === T_DOUBLE_COLON && ($tokens[$index + 1] ?? null)?->id === T_STRING) {
            $arms[] = $tokens[$index + 1]->text;
        }
    }

    expect($hasMatch)->toBeTrue('revokesAccess() must decide with a `match`, so PHPStan can prove it exhaustive.');

    $unhandled = array_values(array_diff(
        array_map(fn (OrganizationStatus $case): string => $case->name, OrganizationStatus::cases()),
        $arms,
    ));

    expect($unhandled)->toBe([], 'OrganizationStatus cases missing from revokesAccess(): '.implode(', ', $unhandled));
});
