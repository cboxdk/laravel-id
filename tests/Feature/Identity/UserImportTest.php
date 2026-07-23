<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\HashVerifier;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\ImportOptions;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Tests\Fixtures\Hashing\ReversibleTestVerifier;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/** The raw, un-cast password column straight from the row. */
function storedHash(string $subjectId): ?string
{
    $model = User::query()->whereKey($subjectId)->first();
    $raw = $model?->getRawOriginal('password');

    return is_string($raw) ? $raw : null;
}

it('imports a real bcrypt hash, authenticates day-one, and upgrades to argon2id on first login', function (): void {
    // Pin the platform hasher to argon2id so the upgrade target is unambiguous.
    config(['hashing.driver' => 'argon2id']);

    $org = $this->makeOrganization();
    $bcrypt = password_hash('s3cret', PASSWORD_BCRYPT); // a genuine foreign hash

    $result = $this->importUsers($org->id, [
        $this->importedUser('alice@corp.test', 'Alice', passwordHash: $bcrypt),
    ]);

    expect($result->imported)->toBe(1)
        ->and($result->failed())->toBeFalse();

    $subjects = app(Subjects::class);
    $id = $subjects->findByEmail('alice@corp.test')?->id ?? '';

    // Stored VERBATIM (still the bcrypt hash) before any login.
    expect(storedHash($id))->toBe($bcrypt);

    // Day-one: the imported bcrypt hash authenticates immediately.
    expect($subjects->verifyPassword($id, 's3cret'))->toBeTrue()
        ->and($subjects->verifyPassword($id, 'wrong'))->toBeFalse();

    // Lazy migration: after that successful login the stored hash is now argon2id
    // and no longer needs a rehash — proven by re-reading the row.
    $upgraded = storedHash($id) ?? '';
    expect($upgraded)->toStartWith('$argon2id$')
        ->and($upgraded)->not->toBe($bcrypt)
        ->and(app(HashVerifier::class)->needsRehash($upgraded))->toBeFalse();

    // Still authenticates with the same password against the upgraded hash.
    expect($subjects->verifyPassword($id, 's3cret'))->toBeTrue();
});

it('imports a plaintext password by hashing it with the platform hasher', function (): void {
    $org = $this->makeOrganization();

    $result = $this->importUsers($org->id, [
        $this->importedUser('bob@corp.test', 'Bob', password: 'plain-text-pw'),
    ]);

    expect($result->imported)->toBe(1);

    $subjects = app(Subjects::class);
    $id = $subjects->findByEmail('bob@corp.test')?->id ?? '';

    expect(storedHash($id))->not->toBe('plain-text-pw') // hashed, not stored raw
        ->and($subjects->verifyPassword($id, 'plain-text-pw'))->toBeTrue()
        ->and($subjects->verifyPassword($id, 'nope'))->toBeFalse();
});

it('is idempotent: skips an existing email, upserts only when asked', function (): void {
    $org = $this->makeOrganization();
    $subjects = app(Subjects::class);

    $this->importUsers($org->id, [$this->importedUser('c@corp.test', 'C', password: 'first')]);
    $id = $subjects->findByEmail('c@corp.test')?->id ?? '';

    // Re-import WITHOUT upsert: skipped, credential untouched.
    $skip = $this->importUsers($org->id, [$this->importedUser('c@corp.test', 'C2', password: 'second')]);
    expect($skip->skipped)->toBe(1)
        ->and($skip->imported)->toBe(0)
        ->and($subjects->verifyPassword($id, 'first'))->toBeTrue()
        ->and($subjects->verifyPassword($id, 'second'))->toBeFalse();

    // Re-import WITH upsert: updated, new credential applied.
    $up = $this->importUsers($org->id, [$this->importedUser('c@corp.test', 'C2', password: 'second')], new ImportOptions(upsert: true));
    expect($up->updated)->toBe(1)
        ->and($subjects->verifyPassword($id, 'second'))->toBeTrue();

    // Still exactly one user for the email.
    expect(User::query()->where('email', 'c@corp.test')->count())->toBe(1);
});

it('rejects an unverifiable hash per-row and never imports it (deny-by-default)', function (): void {
    $org = $this->makeOrganization();
    $subjects = app(Subjects::class);

    $unsupported = '{SSHA}'.base64_encode('digestsalt'); // no native verifier

    $result = $this->importUsers($org->id, [
        $this->importedUser('weak@corp.test', passwordHash: $unsupported),
        $this->importedUser('good@corp.test', password: 'ok'),
    ]);

    // The good row imports; the unverifiable one is a per-row error, not imported.
    expect($result->imported)->toBe(1)
        ->and($result->errorCount())->toBe(1)
        ->and($result->errors[0]->email)->toBe('weak@corp.test')
        ->and($subjects->findByEmail('weak@corp.test'))->toBeNull()
        ->and($subjects->findByEmail('good@corp.test'))->not->toBeNull();
});

it('never authenticates a foreign hash no verifier supports, even stored directly', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('x@corp.test', 'X');

    // Force a raw md5 into the column (deny-by-default must still refuse it).
    $subjects->storeCredential($subject->id, md5('secret'));

    expect($subjects->verifyPassword($subject->id, 'secret'))->toBeFalse()
        ->and($subjects->verifyPassword($subject->id, md5('secret')))->toBeFalse();
});

it('records an invalid email as a per-row error without importing', function (): void {
    $org = $this->makeOrganization();

    $result = $this->importUsers($org->id, [
        $this->importedUser('not-an-email'),
        $this->importedUser('valid@corp.test'),
    ]);

    expect($result->imported)->toBe(1)
        ->and($result->errorCount())->toBe(1)
        ->and($result->errors[0]->row)->toBe(1);
});

it('attaches imported users to the target organization with the right role', function (): void {
    $org = $this->makeOrganization();

    $this->importUsers($org->id, [
        $this->importedUser('m@corp.test', role: 'admin'),
        $this->importedUser('n@corp.test'), // default role
    ]);

    $subjects = app(Subjects::class);
    $memberships = app(Memberships::class);

    $mId = $subjects->findByEmail('m@corp.test')?->id ?? '';
    $nId = $subjects->findByEmail('n@corp.test')?->id ?? '';

    expect($memberships->of($org->id, $mId)?->role?->value)->toBe('admin')
        ->and($memberships->of($org->id, $nId)?->role?->value)->toBe('member');
});

it('honors the email_verified flag per row', function (): void {
    $org = $this->makeOrganization();

    $this->importUsers($org->id, [
        $this->importedUser('v@corp.test', emailVerified: true),
        $this->importedUser('u@corp.test', emailVerified: false),
    ]);

    $subjects = app(Subjects::class);
    $vId = $subjects->findByEmail('v@corp.test')?->id ?? '';
    $uId = $subjects->findByEmail('u@corp.test')?->id ?? '';

    expect(User::query()->whereKey($vId)->first()?->email_verified_at)->not->toBeNull()
        ->and(User::query()->whereKey($uId)->first()?->email_verified_at)->toBeNull();
});

it('lets a host register a verifier for a foreign format — the migration seam', function (): void {
    config(['hashing.driver' => 'argon2id']);
    // Register the host verifier and rebuild the deny-by-default registry.
    config(['cbox-id.hashing.verifiers' => [ReversibleTestVerifier::class]]);
    app()->forgetInstance(HashVerifier::class);
    app()->forgetInstance(Subjects::class);

    $org = $this->makeOrganization();
    $foreign = ReversibleTestVerifier::hash('open-sesame');

    $result = $this->importUsers($org->id, [
        $this->importedUser('firebase@corp.test', passwordHash: $foreign),
    ]);
    expect($result->imported)->toBe(1);

    $subjects = app(Subjects::class);
    $id = $subjects->findByEmail('firebase@corp.test')?->id ?? '';

    expect(storedHash($id))->toBe($foreign) // stored verbatim
        ->and($subjects->verifyPassword($id, 'open-sesame'))->toBeTrue(); // day-one login

    // Upgraded to the platform hasher (argon2id) on that first login.
    expect(storedHash($id))->toStartWith('$argon2id$');
});
