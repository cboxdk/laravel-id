<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\AdminPasswords;
use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\PasswordReset;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\PasswordRevocationScope;
use Cbox\Id\Identity\Exceptions\PolicyViolation;
use Cbox\Id\Identity\ValueObjects\AdminPasswordAssignment;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Testing\InteractsWithOrganizations;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithOrganizations::class);

/**
 * The review found the policy enforced on two paths out of many: an environment
 * demanding 24 characters got whatever floor the calling form happened to hardcode
 * everywhere else. These tests exist to make that regression loud — each one drives a
 * DIFFERENT way a credential can be set, and every one of them must refuse.
 */
beforeEach(function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(minLength: 24));
});

/** A password comfortably above the DEFAULT floor of 12, but below this tenant's 24. */
const UNDER_TENANT_FLOOR = 'sixteen-chars-xx';

it('refuses a sub-policy password at signup', function (): void {
    expect(fn () => app(Subjects::class)->create('new@corp.test', 'New', UNDER_TENANT_FLOOR))
        ->toThrow(PolicyViolation::class);

    expect(app(Subjects::class)->findByEmail('new@corp.test'))->toBeNull();
});

it('refuses a sub-policy password on the setPassword primitive', function (): void {
    $subject = app(Subjects::class)->create('sam@corp.test', 'Sam', 'a-perfectly-long-original-passphrase');

    expect(fn () => app(Subjects::class)->setPassword($subject->id, UNDER_TENANT_FLOOR))
        ->toThrow(PolicyViolation::class);

    // The old credential still stands — a refused change is not a silent wipe.
    expect(app(Subjects::class)->verifyPassword($subject->id, 'a-perfectly-long-original-passphrase'))->toBeTrue();
});

it('refuses a sub-policy password on self-service reset', function (): void {
    app(Subjects::class)->create('sam@corp.test', 'Sam', 'a-perfectly-long-original-passphrase');

    $token = app(PasswordReset::class)->request('sam@corp.test') ?? '';

    expect(fn () => app(PasswordReset::class)->reset($token, UNDER_TENANT_FLOOR))
        ->toThrow(PolicyViolation::class);
});

it('refuses a sub-policy password on administrative assignment', function (): void {
    $subject = app(Subjects::class)->create('sam@corp.test', 'Sam', 'a-perfectly-long-original-passphrase');

    expect(fn () => app(AdminPasswords::class)->assign(new AdminPasswordAssignment(
        userId: $subject->id,
        password: UNDER_TENANT_FLOOR,
        temporary: true,
        revoke: PasswordRevocationScope::Nothing,
    )))->toThrow(PolicyViolation::class);
});

/**
 * The primitive is handed a subject and nothing else, so it has to work out which
 * organizations bind that subject. Resolving the bare environment baseline instead
 * would let a member of a strict organization sidestep it through any path that
 * happened not to carry org context.
 */
it("applies an organization's tightened policy even when the caller names no organization", function (): void {
    $policies = app(AuthPolicies::class);
    $policies->setForEnvironment(new AuthPolicy(minLength: 12));

    $org = $this->makeOrganization();
    $policies->setForOrganization($org->id, new AuthPolicy(minLength: 32));

    $subject = app(Subjects::class)->create('strict@corp.test', 'Strict', 'a-perfectly-long-original-passphrase');
    app(Memberships::class)->add($org->id, $subject->id, 'member');

    // Satisfies the environment's 12, not the organization's 32.
    expect(fn () => app(Subjects::class)->setPassword($subject->id, 'sixteen-chars-xx'))
        ->toThrow(PolicyViolation::class);

    app(Subjects::class)->setPassword($subject->id, 'a-passphrase-of-a-full-thirty-two');
    expect(app(Subjects::class)->verifyPassword($subject->id, 'a-passphrase-of-a-full-thirty-two'))->toBeTrue();
});

/** Reuse history is only useful if every path writes to it, not just the two that did. */
it('records the passwords a subject actually chose, so reuse is caught across paths', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(minLength: 12, reuseHistory: 3));

    $subjects = app(Subjects::class);
    $subject = $subjects->create('history@corp.test', 'History', 'the-signup-passphrase');

    $subjects->setPassword($subject->id, 'the-second-passphrase');

    // Both the signup password and the later change are remembered.
    expect(fn () => $subjects->setPassword($subject->id, 'the-signup-passphrase'))
        ->toThrow(PolicyViolation::class);
    expect(fn () => $subjects->setPassword($subject->id, 'the-second-passphrase'))
        ->toThrow(PolicyViolation::class);
});
