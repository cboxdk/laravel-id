<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\HashVerifier;
use Cbox\Id\Migration\Sources\DatabaseCredentialSource;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    // A stand-in for the old application's own table, on the same connection because the
    // point under test is the mapping and the hash, not Laravel's connection resolution.
    Schema::create('legacy_users', function (Blueprint $table): void {
        $table->increments('id');
        $table->string('email_address');
        $table->string('full_name')->nullable();
        $table->string('pass');
        $table->timestamp('confirmed_at')->nullable();
    });
});

function legacySource(): DatabaseCredentialSource
{
    return new DatabaseCredentialSource(
        app('db'),
        app(HashVerifier::class),
        connection: config('database.default'),
        table: 'legacy_users',
        columns: ['email' => 'email_address', 'name' => 'full_name', 'password' => 'pass', 'verified_at' => 'confirmed_at'],
    );
}

it('verifies against the old table and hands back the person', function (): void {
    DB::table('legacy_users')->insert([
        'email_address' => 'ada@legacy.test',
        'full_name' => 'Ada Lovelace',
        'pass' => password_hash('correct horse', PASSWORD_BCRYPT),
        'confirmed_at' => now(),
    ]);

    $user = legacySource()->verify('ada@legacy.test', 'correct horse');

    expect($user?->email)->toBe('ada@legacy.test')
        ->and($user?->name)->toBe('Ada Lovelace')
        ->and($user?->emailVerified)->toBeTrue()
        // The HASH travels, not the plaintext — so the caller can store it verbatim and
        // the upgrade-on-login path treats them like any imported user.
        ->and($user?->passwordHash)->toStartWith('$2y$');
});

it('says no to a wrong password', function (): void {
    DB::table('legacy_users')->insert([
        'email_address' => 'ada@legacy.test',
        'pass' => password_hash('correct horse', PASSWORD_BCRYPT),
    ]);

    expect(legacySource()->verify('ada@legacy.test', 'wrong'))->toBeNull();
});

/**
 * The old system almost certainly stored whatever the person typed at signup. A
 * case-sensitive comparison silently skips everyone who capitalised anything — and the
 * symptom is "migration works for most people", which is the worst kind of bug to chase.
 */
it('matches an address the old system stored with different capitalisation', function (): void {
    DB::table('legacy_users')->insert([
        'email_address' => 'Ada@Legacy.TEST',
        'pass' => password_hash('correct horse', PASSWORD_BCRYPT),
    ]);

    expect(legacySource()->verify('ada@legacy.test', 'correct horse'))->not->toBeNull();
});

/**
 * An SSO-only account in the old system, or a half-created one. Not a credential we can
 * verify, and not an error either.
 */
it('says no to a row with no password at all', function (): void {
    DB::table('legacy_users')->insert(['email_address' => 'sso@legacy.test', 'pass' => '']);

    expect(legacySource()->verify('sso@legacy.test', 'anything'))->toBeNull();
});

/**
 * A table or column name from configuration is interpolated into SQL — `LOWER(<column>)`
 * cannot be a bound parameter — so a name nobody checked is an injection point the moment
 * configuration is writable by anything but a person.
 */
it('refuses an identifier that is not a bare table or column name', function (): void {
    expect(fn () => new DatabaseCredentialSource(
        app('db'),
        app(HashVerifier::class),
        connection: config('database.default'),
        table: 'legacy_users',
        columns: ['email' => 'email) = ? OR 1=1 --', 'password' => 'pass'],
    ))->toThrow(InvalidArgumentException::class);
});

/**
 * FAIL CLOSED at this layer too: a missing table is not "no such user", it is "I could not
 * decide", and the caller turns both into a refusal.
 */
it('says no rather than exploding when the old table is unreachable', function (): void {
    Schema::drop('legacy_users');

    expect(legacySource()->verify('ada@legacy.test', 'correct horse'))->toBeNull();
});
