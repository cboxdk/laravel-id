<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Contracts\PlatformOperators;
use Cbox\Id\Platform\Models\PlatformOperator;
use Cbox\Id\Platform\PlatformRoot;
use Illuminate\Foundation\Testing\RefreshDatabase;

/**
 * An operator is a person, not a second credential store.
 *
 * Everything that protects a sign-in on this platform lives on the subject — password
 * policy, breached-password refusal, lockout, TOTP, passkeys, step-up, session
 * revocation. An operator had none of it: `platform_operators` held an email and a
 * bcrypt hash. The widest reach in the product sat behind the weakest door, and it was
 * weakest because it was separate. Account members went through this already.
 */
uses(RefreshDatabase::class);

function aPlatformRoot(): Environment
{
    return Environment::query()->create([
        'name' => 'Production',
        'slug' => 'production-root',
        'status' => 'active',
        'is_default' => true,
        'settings' => [],
    ]);
}

it('gives a new operator an ordinary subject', function (): void {
    aPlatformRoot();

    $operator = app(PlatformOperators::class)->create('staff@cbox.test', 'a-strong-unbreached-passphrase', 'Staff');

    expect($operator->refresh()->subject_id)->not->toBeNull();

    // In the PLATFORM ROOT, not the ambient scope. Subjects are environment-owned, so
    // creating one under whatever environment happened to be current would file the
    // platform's own staff inside a tenant.
    $subject = app(PlatformRoot::class)->run(
        fn () => app(Subjects::class)->find((string) $operator->refresh()->subject_id),
    );

    expect($subject?->email)->toBe('staff@cbox.test');
})->group('security');

it('authenticates an operator against the subject, not the local hash', function (): void {
    aPlatformRoot();

    $operators = app(PlatformOperators::class);
    $operator = $operators->create('staff@cbox.test', 'a-strong-unbreached-passphrase');

    expect($operators->verifyPassword($operator->id, 'a-strong-unbreached-passphrase'))->toBeTrue();

    // Corrupt the LOCAL hash. If authentication still succeeds, the subject is the
    // credential of record — which is the whole point. If it fails, the local hash is
    // still in the path and nothing has actually moved.
    PlatformOperator::query()->whereKey($operator->id)->update(['password' => bcrypt('something-else-entirely')]);

    expect($operators->verifyPassword($operator->id, 'a-strong-unbreached-passphrase'))->toBeTrue();
})->group('security');

it('refuses an operator whose subject has been deactivated', function (): void {
    aPlatformRoot();

    $operators = app(PlatformOperators::class);
    $operator = $operators->create('staff@cbox.test', 'a-strong-unbreached-passphrase');

    // Revoking the person revokes the operator — the reach of a platform operator is why
    // that has to be immediate rather than at the next session boundary.
    app(PlatformRoot::class)->run(function () use ($operator): void {
        app(Subjects::class)->deactivate((string) $operator->refresh()->subject_id);
    });

    expect($operators->verifyPassword($operator->id, 'a-strong-unbreached-passphrase'))->toBeFalse();
})->group('security');

it('reuses the subject of a person who is already known', function (): void {
    aPlatformRoot();

    $existing = app(PlatformRoot::class)->run(
        fn () => app(Subjects::class)->create('staff@cbox.test', 'Staff', 'a-strong-unbreached-passphrase'),
    );

    $operator = app(PlatformOperators::class)->create('staff@cbox.test', 'a-strong-unbreached-passphrase');

    // Two subjects for one human at one address is the id-space split this ends.
    expect($operator->refresh()->subject_id)->toBe($existing?->id);
})->group('security');

it('falls back to the local hash only until a platform root exists', function (): void {
    // The very first install: no default environment, so there is nowhere for a subject
    // to live. The operator must still be able to sign in.
    $operators = app(PlatformOperators::class);
    $operator = $operators->create('first@cbox.test', 'a-strong-unbreached-passphrase');

    expect($operator->refresh()->subject_id)->toBeNull()
        ->and($operators->verifyPassword($operator->id, 'a-strong-unbreached-passphrase'))->toBeTrue();

    // Once a root exists, the next successful sign-in attaches the subject — the only
    // moment the plaintext is available to seed it.
    aPlatformRoot();

    expect($operators->verifyPassword($operator->id, 'a-strong-unbreached-passphrase'))->toBeTrue()
        ->and($operator->refresh()->subject_id)->not->toBeNull();
})->group('security');

it('refuses a wrong password during the bootstrap window', function (): void {
    $operators = app(PlatformOperators::class);
    $operator = $operators->create('first@cbox.test', 'a-strong-unbreached-passphrase');

    expect($operators->verifyPassword($operator->id, 'not-the-password'))->toBeFalse()
        ->and($operator->refresh()->subject_id)->toBeNull();
})->group('security');

/**
 * The lookup that makes operator authority a permission.
 *
 * A console can now ask "is the session I already have staff?" instead of standing up a
 * second sign-in beside the first. That is the whole reason the two identities were
 * unified: the separate operator door existed only because there was a separate operator
 * credential, and there no longer is one.
 */
it('finds an operator by the subject that signs in as them', function (): void {
    aPlatformRoot();

    $operator = app(PlatformOperators::class)->create('staff@cbox.test', 'a-strong-unbreached-passphrase', 'Staff');
    $subjectId = $operator->refresh()->subject_id;

    expect($subjectId)->not->toBeNull()
        ->and(app(PlatformOperators::class)->findBySubject((string) $subjectId)?->id)->toBe($operator->id);
});

/**
 * Suspension has to reach the RAIL, not only the sign-in.
 *
 * With authority carried by an existing session, a suspended operator is still signed in
 * — their subject is untouched, and suspending an operator has never revoked subject
 * sessions. If the lookup ignored status, suspension would take away the ability to sign
 * in again while leaving every platform page reachable in the session they already hold,
 * which is the opposite of what suspending someone means.
 */
it('refuses to answer for a suspended operator', function (): void {
    aPlatformRoot();

    $operators = app(PlatformOperators::class);
    // Two, because the platform refuses to suspend its last remaining operator.
    $operator = $operators->create('staff@cbox.test', 'a-strong-unbreached-passphrase', 'Staff');
    $other = $operators->create('other@cbox.test', 'a-strong-unbreached-passphrase', 'Other');

    $subjectId = (string) $operator->refresh()->subject_id;

    expect($operators->findBySubject($subjectId))->not->toBeNull();

    $operators->suspend($operator->id, $other->id);

    expect($operators->findBySubject($subjectId))
        ->toBeNull('a suspended operator kept their platform pages in the session they already held');
});
