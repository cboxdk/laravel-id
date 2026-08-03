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

/**
 * Run the upgrade migration by hand.
 *
 * `RefreshDatabase` has already run it once — before these fixtures existed, when there
 * was nothing to carry across — so the test has to invoke it against the state it is
 * actually about. Required from the file rather than named: migrations are anonymous
 * classes, which is what keeps two of them from colliding on a class name.
 */
function runOperatorSubjectMigration(): void
{
    $migration = require __DIR__.'/../../database/migrations/2026_08_05_000100_give_every_existing_operator_a_subject.php';
    $migration->up();
}

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

/**
 * The upgrade path, which is the half that would have locked a live deployment out.
 *
 * `verifyPassword()` attaches a subject on the operator's next successful sign-in, and
 * that was enough while a sign-in existed that verified against the local hash. Operator
 * authority is a permission on the ordinary sign-in now, and the separate operator login
 * form — the only caller that reached the bootstrap window — went with it. So every
 * operator carried across from before the unification has no subject, no account to sign
 * in as, and no door left that consults their hash.
 *
 * The plaintext is gone but the hash is not, and it does not need re-deriving: both
 * tables hash with the configured driver and both models pass an already-hashed value
 * through untouched. So the credential moves, and the password keeps working.
 */
it('carries a pre-unification operator across to a subject they can sign in as', function (): void {
    $root = aPlatformRoot();

    // An operator exactly as an upgraded deployment holds one: a local hash, no subject.
    $operator = PlatformOperator::query()->create([
        'email' => 'legacy@cbox.test',
        'name' => 'Legacy',
        'password' => 'a-strong-unbreached-passphrase',
        'status' => 'active',
    ]);

    expect($operator->refresh()->subject_id)->toBeNull();

    runOperatorSubjectMigration();

    $subjectId = $operator->refresh()->subject_id;

    expect($subjectId)->not->toBeNull()
        ->and(app(PlatformOperators::class)->findBySubject((string) $subjectId)?->id)->toBe($operator->id);

    // The password still works — through the SUBJECT, which is the only door left.
    $subject = app(PlatformRoot::class)->run(
        fn () => app(Subjects::class)->findByEmail('legacy@cbox.test'),
    );

    expect($subject?->id)->toBe($subjectId)
        ->and(app(PlatformRoot::class)->run(
            fn (): bool => app(Subjects::class)->verifyPassword($subject->id, 'a-strong-unbreached-passphrase'),
        ))->toBeTrue('the operator was carried across but their password no longer opens anything');
});

/**
 * An operator who is ALSO an account member already has a subject at that address.
 * Giving them a second one is the id-space split this change exists to end — and it
 * would leave two passwords for one person, of which only one is the live one.
 */
it('reuses the subject an operator already has rather than minting a second', function (): void {
    aPlatformRoot();

    $existing = app(PlatformRoot::class)->run(
        fn () => app(Subjects::class)->create('both@cbox.test', 'Both', 'their-own-live-passphrase'),
    );

    $operator = PlatformOperator::query()->create([
        'email' => 'both@cbox.test',
        'name' => 'Both',
        'password' => 'a-stale-operator-passphrase',
        'status' => 'active',
    ]);

    runOperatorSubjectMigration();

    expect($operator->refresh()->subject_id)->toBe($existing->id);

    // And their live password is untouched — the operator hash may be the older of the two.
    expect(app(PlatformRoot::class)->run(
        fn (): bool => app(Subjects::class)->verifyPassword($existing->id, 'their-own-live-passphrase'),
    ))->toBeTrue('the migration overwrote a live account password with a stale operator hash');
});
